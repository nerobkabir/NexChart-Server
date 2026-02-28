"use strict";

// ============================================================
// index.js — Connect Messaging App · Single-File Backend
// ============================================================
// Architecture at a glance:
//
//  [Client] ──HTTP──▶ Express Routes   ──▶ MongoDB (Mongoose)
//  [Client] ──WS───▶  Socket.io Server ──▶ MongoDB (Mongoose)
//
//  Auth flow:
//    Register/Login  → bcrypt hash  → JWT  → httpOnly cookie
//    Protected route → cookie parse → JWT verify → req.user
//    Socket connect  → handshake.auth.token OR cookie → JWT verify
//
//  Real-time event map:
//    Client emits  → Server handles → Server emits to room
//    "msg:send"    →  save to DB    → "msg:new" (conv room)
//    "typing:on"   →  in-memory     → "typing" (conv room)
//    "typing:off"  →  in-memory     → "typing" (conv room)
//    "msg:read"    →  DB update     → "msg:read" (conv room)
//    disconnect    →  DB update     → "presence" (broadcast)
// ============================================================


// ====================== IMPORTS ======================

const express       = require("express");
const http          = require("http");
const { Server }    = require("socket.io");
const mongoose      = require("mongoose");
const bcrypt        = require("bcryptjs");
const jwt           = require("jsonwebtoken");
const cookieParser  = require("cookie-parser");
const cors          = require("cors");
const helmet        = require("helmet");
const rateLimit     = require("express-rate-limit");
const mongoSanitize = require("express-mongo-sanitize");
const xss           = require("xss");
require("dotenv").config();

// ====================== BOOTSTRAP ======================

const app    = express();
app.set("trust proxy", 1);
const server = http.createServer(app);


// ====================== ENVIRONMENT / CONSTANTS ======================

const PORT       = process.env.PORT       || 5000;
const MONGO_URI  = process.env.MONGO_URI  || "mongodb://127.0.0.1:27017/connect_db";
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_IN_PRODUCTION_MIN_32_CHARS";
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:3000";

// JWT expires in 7 days; cookie mirrors the same lifetime
const JWT_EXPIRES_IN    = "7d";
const COOKIE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;


// ====================== DATABASE CONNECTION ======================

mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✅  MongoDB connected:", MONGO_URI))
  .catch((err) => {
    console.error("❌  MongoDB connection error:", err.message);
    process.exit(1);
  });

// Graceful shutdown: close Mongo on SIGTERM / SIGINT
const gracefulShutdown = async (signal) => {
  console.log(`\n${signal} received — closing server…`);
  server.close(async () => {
    await mongoose.connection.close();
    console.log("MongoDB connection closed. Bye! 👋");
    process.exit(0);
  });
};
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT",  () => gracefulShutdown("SIGINT"));


// ====================== MONGOOSE SCHEMAS ======================

// ── User ──────────────────────────────────────────────────────
const userSchema = new mongoose.Schema(
  {
    name: {
      type:      String,
      required:  [true, "Name is required"],
      trim:      true,
      maxlength: [60, "Name cannot exceed 60 characters"],
    },
    email: {
      type:      String,
      required:  [true, "Email is required"],
      unique:    true,
      lowercase: true,
      trim:      true,
      match:     [/^\S+@\S+\.\S+$/, "Invalid email format"],
    },
    password: {
      type:      String,
      required:  [true, "Password is required"],
      minlength: [6, "Password must be at least 6 characters"],
      select:    false,          // Never returned in queries by default
    },
    avatar: {
      type:    String,
      default: "",               // URL; use DiceBear or Cloudinary
    },
    about: {
      type:      String,
      default:   "Hey there! I'm using Connect.",
      maxlength: [150, "About cannot exceed 150 characters"],
    },
    isOnline: {
      type:    Boolean,
      default: false,
    },
    lastSeen: {
      type:    Date,
      default: Date.now,
    },
    // Stores the socket ID so we can target direct personal room
    socketId: {
      type:    String,
      default: null,
      select:  false,
    },
  },
  { timestamps: true }
);

// Indexes ─────────────────────────────────────────────────────
// email is already indexed via `unique: true`.
// isOnline is queried when listing online users for presence.
userSchema.index({ isOnline: 1 });

// Pre-save: hash password only when it is new/modified
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  const salt   = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Instance helpers
userSchema.methods.comparePassword = function (candidate) {
  return bcrypt.compare(candidate, this.password);
};

userSchema.methods.toPublicJSON = function () {
  return {
    _id:      this._id,
    name:     this.name,
    email:    this.email,
    avatar:   this.avatar,
    about:    this.about,
    isOnline: this.isOnline,
    lastSeen: this.lastSeen,
  };
};

const User = mongoose.model("User", userSchema);


// ── Conversation ──────────────────────────────────────────────
const conversationSchema = new mongoose.Schema(
  {
    // Always exactly two participants for 1-on-1 chat
    participants: [
      {
        type:     mongoose.Schema.Types.ObjectId,
        ref:      "User",
        required: true,
      },
    ],
    // Denormalised pointer to the most recent message for sidebar preview
    lastMessage: {
      type:    mongoose.Schema.Types.ObjectId,
      ref:     "Message",
      default: null,
    },
    // Per-user unread counters stored as a plain object:
    // { "<userId>": <Number> }
    // Using Mixed + markModified avoids the overhead of a sub-document.
    unreadCounts: {
      type:    mongoose.Schema.Types.Mixed,
      default: {},
    },
  },
  {
    // updatedAt is used to sort the sidebar list by last activity
    timestamps: true,
  }
);

// Indexes ─────────────────────────────────────────────────────
// Primary lookup: find the conversation between two specific users
conversationSchema.index({ participants: 1 });
// Sidebar list is sorted by most-recent activity
conversationSchema.index({ updatedAt: -1 });

// Static: find an existing 1-on-1 conversation or create a new one
conversationSchema.statics.findOrCreate = async function (userIdA, userIdB) {
  let conv = await this.findOne({
    participants: { $all: [userIdA, userIdB], $size: 2 },
  });
  if (!conv) {
    conv = await this.create({
      participants:  [userIdA, userIdB],
      unreadCounts:  { [userIdA]: 0, [userIdB]: 0 },
    });
  }
  return conv;
};

const Conversation = mongoose.model("Conversation", conversationSchema);


// ── Message ───────────────────────────────────────────────────
const messageSchema = new mongoose.Schema(
  {
    conversationId: {
      type:     mongoose.Schema.Types.ObjectId,
      ref:      "Conversation",
      required: true,
    },
    sender: {
      type:     mongoose.Schema.Types.ObjectId,
      ref:      "User",
      required: true,
    },
    text: {
      type:      String,
      required:  [true, "Message text is required"],
      trim:      true,
      maxlength: [2000, "Message cannot exceed 2000 characters"],
    },
    // IDs of users who have read this message (not including the sender)
    readBy: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref:  "User",
      },
    ],
    // Soft-delete flag: replaced with "This message was deleted."
    isDeleted: {
      type:    Boolean,
      default: false,
    },
  },
  { timestamps: true }
);

// Indexes ─────────────────────────────────────────────────────
// Most critical index: fetching messages for a conversation ordered by time.
// The compound index supports: db.messages.find({ conversationId }).sort({ createdAt: -1 })
messageSchema.index({ conversationId: 1, createdAt: -1 });

const Message = mongoose.model("Message", messageSchema);


// ====================== EXPRESS MIDDLEWARE STACK ======================

// 1. Security headers (CSP etc.)
app.use(
  helmet({
    // Allow inline scripts/styles for the front-end dev server
    contentSecurityPolicy: process.env.NODE_ENV === "production",
  })
);

// 2. CORS — allow the front-end origin and send cookies cross-origin
app.use(
  cors({
    origin:      CLIENT_URL,
    credentials: true,                   // Required for httpOnly cookies
    methods:     ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// 3. Body parsers + cookie parser
app.use(express.json({ limit: "10kb" }));            // Reject huge bodies
app.use(express.urlencoded({ extended: true, limit: "10kb" }));
app.use(cookieParser());

// 4. NoSQL injection protection (strips keys starting with "$" or ".")
app.use(mongoSanitize());

// 5. Rate limiters
//    Global limiter: 300 requests per 15 min per IP
const globalLimiter = rateLimit({
  windowMs:        15 * 60 * 1000,
  max:             300,
  standardHeaders: true,
  legacyHeaders:   false,
  message:         { error: "Too many requests — please slow down." },
});

//    Auth limiter: much stricter to prevent brute-force
const authLimiter = rateLimit({
  windowMs:        15 * 60 * 1000,
  max:             15,
  standardHeaders: true,
  legacyHeaders:   false,
  message:         { error: "Too many auth attempts — try again in 15 minutes." },
});

app.use(globalLimiter);


// ====================== AUTH UTILITIES ======================

/**
 * Sign a JWT, set it as an httpOnly cookie, and return the raw token.
 * httpOnly → inaccessible to JavaScript (XSS safe)
 * secure   → HTTPS only in production
 * sameSite → "none" in production (cross-origin) / "lax" in development
 */
const issueToken = (res, userId) => {
  const token = jwt.sign({ id: userId }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
  });

  res.cookie("token", token, {
    httpOnly: true,
    secure:   process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    maxAge:   COOKIE_MAX_AGE_MS,
  });

  return token;
};

/**
 * Clear the auth cookie (used on logout).
 */
const clearToken = (res) => {
  res.cookie("token", "", {
    httpOnly: true,
    secure:   process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    maxAge:   0,
  });
};

/**
 * XSS-sanitise every string field in an object (shallow + 1 level deep).
 * Keeps the app's critical path lean without a heavy sanitization library.
 */
const sanitize = (obj) => {
  if (!obj || typeof obj !== "object") return obj;
  const clean = {};
  for (const [key, val] of Object.entries(obj)) {
    if (typeof val === "string") {
      clean[key] = xss(val.trim());
    } else if (typeof val === "object" && val !== null && !Array.isArray(val)) {
      clean[key] = sanitize(val);      // One level of recursion is enough
    } else {
      clean[key] = val;
    }
  }
  return clean;
};


// ====================== AUTH MIDDLEWARE ======================

/**
 * HTTP route guard.
 * Reads the JWT from the httpOnly cookie (preferred) or
 * the Authorization: Bearer <token> header (useful for API clients).
 * Attaches the full user document to req.user.
 */
const protect = async (req, res, next) => {
  try {
    let token = req.cookies?.token;

    // Fallback: allow Bearer token for non-browser clients / testing
    if (!token && req.headers.authorization?.startsWith("Bearer ")) {
      token = req.headers.authorization.split(" ")[1];
    }

    if (!token) {
      return res.status(401).json({ error: "Not authenticated. Please log in." });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    const user = await User.findById(decoded.id).select("-password -socketId");
    if (!user) {
      return res.status(401).json({ error: "User account no longer exists." });
    }

    req.user = user;
    next();
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Session expired. Please log in again." });
    }
    if (err.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid token. Please log in again." });
    }
    next(err);
  }
};

/**
 * Socket.io authentication middleware.
 * The client must pass the JWT via:
 *   socket = io(URL, { auth: { token: "<jwt>" } })
 *
 * If the client is browser-based with cookies, we parse the cookie header
 * as a fallback (no extra client-side work needed).
 */
const protectSocket = async (socket, next) => {
  try {
    // Priority 1: explicit token in handshake auth object
    let token = socket.handshake.auth?.token;

    // Priority 2: parse cookie header (browser clients)
    if (!token) {
      const cookieHeader = socket.handshake.headers?.cookie || "";
      const match = cookieHeader.match(/(?:^|;\s*)token=([^;]+)/);
      if (match) token = match[1];
    }

    if (!token) {
      return next(new Error("Socket: authentication required."));
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user    = await User.findById(decoded.id).select("-password");

    if (!user) {
      return next(new Error("Socket: user not found."));
    }

    // Attach user to socket so every handler can access it without a DB call
    socket.user = user;
    next();
  } catch (err) {
    next(new Error("Socket: invalid or expired token."));
  }
};


// ====================== ROUTES ======================

const router = express.Router();

// ── Health check ──────────────────────────────────────────────
router.get("/health", (_req, res) => {
  res.json({
    status:    "ok",
    service:   "connect-api",
    timestamp: new Date().toISOString(),
    mongo:     mongoose.connection.readyState === 1 ? "connected" : "disconnected",
  });
});


// ── Auth ─────────────────────────────────────────────────────
// POST /api/auth/register
router.post("/auth/register", authLimiter, async (req, res, next) => {
  try {
    const body = sanitize(req.body);
    const { name, email, password } = body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: "name, email, and password are required." });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters." });
    }

    const exists = await User.findOne({ email });
    if (exists) {
      return res.status(409).json({ error: "An account with this email already exists." });
    }

    const user = await User.create({
      name,
      email,
      password,
      // Auto-generate a DiceBear avatar from the user's name seed
      avatar: `https://api.dicebear.com/7.x/initials/svg?seed=${encodeURIComponent(name)}`,
    });

    const token = issueToken(res, user._id);

    res.status(201).json({
      message: "Account created successfully.",
      user:    user.toPublicJSON(),
      token,   // Also returned in body for non-browser clients
    });
  } catch (err) {
    // Mongoose duplicate key
    if (err.code === 11000) {
      return res.status(409).json({ error: "Email is already registered." });
    }
    next(err);
  }
});

// POST /api/auth/login
router.post("/auth/login", authLimiter, async (req, res, next) => {
  try {
    const body = sanitize(req.body);
    const { email, password } = body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required." });
    }

    // Explicitly select password (it's `select: false` on the schema)
    const user = await User.findOne({ email }).select("+password");

    if (!user || !(await user.comparePassword(password))) {
      // Same error message for both cases — prevents user enumeration
      return res.status(401).json({ error: "Invalid email or password." });
    }

    const token = issueToken(res, user._id);

    res.json({
      message: "Logged in successfully.",
      user:    user.toPublicJSON(),
      token,
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/auth/logout
router.post("/auth/logout", protect, async (req, res, next) => {
  try {
    // Mark user offline on logout (socket disconnect also does this,
    // but the user may have already closed the socket tab)
    await User.findByIdAndUpdate(req.user._id, {
      isOnline: false,
      lastSeen: new Date(),
      socketId: null,
    });

    clearToken(res);
    res.json({ message: "Logged out successfully." });
  } catch (err) {
    next(err);
  }
});

// GET /api/auth/me
router.get("/auth/me", protect, (req, res) => {
  res.json({ user: req.user.toPublicJSON() });
});


// ── Users ─────────────────────────────────────────────────────
// GET /api/users/search?q=<query>
// Search users to start a new conversation
router.get("/users/search", protect, async (req, res, next) => {
  try {
    const q = xss((req.query.q || "").trim());
    if (!q) {
      return res.status(400).json({ error: "Search query is required." });
    }

    const regex = new RegExp(q, "i");  // Case-insensitive

    const users = await User.find({
      _id:   { $ne: req.user._id },    // Exclude self
      $or:   [{ name: regex }, { email: regex }],
    })
      .select("_id name email avatar isOnline lastSeen about")
      .limit(20)
      .lean();

    res.json({ users });
  } catch (err) {
    next(err);
  }
});

// GET /api/users/:id
router.get("/users/:id", protect, async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id)
      .select("_id name email avatar isOnline lastSeen about");

    if (!user) return res.status(404).json({ error: "User not found." });
    res.json({ user });
  } catch (err) {
    next(err);
  }
});

// PUT /api/users/profile  — update own profile
router.put("/users/profile", protect, async (req, res, next) => {
  try {
    const body = sanitize(req.body);

    const allowed = {};
    if (body.name   !== undefined) allowed.name   = body.name;
    if (body.about  !== undefined) allowed.about  = body.about;
    if (body.avatar !== undefined) allowed.avatar = body.avatar;

    if (Object.keys(allowed).length === 0) {
      return res.status(400).json({ error: "Provide at least one field to update." });
    }

    const user = await User.findByIdAndUpdate(req.user._id, allowed, {
      new:             true,
      runValidators:   true,
    });

    res.json({ message: "Profile updated.", user: user.toPublicJSON() });
  } catch (err) {
    next(err);
  }
});


// ── Conversations ─────────────────────────────────────────────
// GET /api/conversations  — get all conversations for current user
router.get("/conversations", protect, async (req, res, next) => {
  try {
    const conversations = await Conversation.find({
      participants: req.user._id,
    })
      .populate("participants", "_id name email avatar isOnline lastSeen")
      .populate({
        path:     "lastMessage",
        select:   "text sender createdAt isDeleted",
        populate: { path: "sender", select: "name" },
      })
      .sort({ updatedAt: -1 })
      .lean();

    // Attach per-user unread count and resolve the "other" participant
    const result = conversations.map((conv) => ({
      ...conv,
      unreadCount: conv.unreadCounts?.[req.user._id.toString()] || 0,
      contact: conv.participants.find(
        (p) => p._id.toString() !== req.user._id.toString()
      ),
    }));

    res.json({ conversations: result });
  } catch (err) {
    next(err);
  }
});

// POST /api/conversations  — find or create a 1-on-1 conversation
router.post("/conversations", protect, async (req, res, next) => {
  try {
    const { recipientId } = sanitize(req.body);

    if (!recipientId) {
      return res.status(400).json({ error: "recipientId is required." });
    }
    if (recipientId === req.user._id.toString()) {
      return res.status(400).json({ error: "Cannot create a conversation with yourself." });
    }

    const recipient = await User.findById(recipientId);
    if (!recipient) return res.status(404).json({ error: "Recipient not found." });

    const conv = await Conversation.findOrCreate(req.user._id, recipientId);

    await conv.populate("participants", "_id name email avatar isOnline lastSeen");
    await conv.populate({
      path:     "lastMessage",
      select:   "text sender createdAt",
      populate: { path: "sender", select: "name" },
    });

    res.json({
      conversation: {
        ...conv.toObject(),
        unreadCount: conv.unreadCounts?.[req.user._id.toString()] || 0,
        contact: conv.participants.find(
          (p) => p._id.toString() !== req.user._id.toString()
        ),
      },
    });
  } catch (err) {
    next(err);
  }
});


// ── Messages ─────────────────────────────────────────────────
// GET /api/messages/:conversationId?limit=20&before=<ISO_timestamp>
//
// Pagination strategy: cursor-based using `before` timestamp.
//   - First page:  no `before` → returns the 20 most recent messages
//   - Next pages:  pass `before=<createdAt of oldest message in current batch>`
//   - This avoids SKIP which degrades badly at large offsets.
router.get("/messages/:conversationId", protect, async (req, res, next) => {
  try {
    const { conversationId } = req.params;
    const limit  = Math.min(parseInt(req.query.limit, 10) || 20, 50);
    const before = req.query.before;   // ISO 8601 datetime string

    // Authorisation: ensure the caller is a participant
    const conv = await Conversation.findOne({
      _id:          conversationId,
      participants: req.user._id,
    });
    if (!conv) {
      return res.status(403).json({ error: "Access denied to this conversation." });
    }

    // Build query — optionally scope to messages older than the cursor
    const query = { conversationId };
    if (before) {
      query.createdAt = { $lt: new Date(before) };
    }

    const messages = await Message.find(query)
      .sort({ createdAt: -1 })      // Newest first; reversed below
      .limit(limit)
      .populate("sender", "_id name avatar")
      .lean();

    // Mark all messages from the other party as read
    await Message.updateMany(
      {
        conversationId,
        sender:           { $ne: req.user._id },
        readBy:           { $ne: req.user._id },
      },
      { $addToSet: { readBy: req.user._id } }
    );

    // Reset unread counter for this user
    await Conversation.findByIdAndUpdate(conversationId, {
      $set: { [`unreadCounts.${req.user._id}`]: 0 },
    });

    res.json({
      messages:   messages.reverse(),   // Return chronological order
      pagination: {
        limit,
        returned: messages.length,
        hasMore:  messages.length === limit,
        // Client uses this as the `before` value for the next request
        nextCursor: messages.length > 0 ? messages[0].createdAt : null,
      },
    });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/messages/:messageId  — soft-delete own message
router.delete("/messages/:messageId", protect, async (req, res, next) => {
  try {
    const message = await Message.findOne({
      _id:    req.params.messageId,
      sender: req.user._id,     // Only the sender may delete
    });

    if (!message) {
      return res.status(404).json({ error: "Message not found or not yours to delete." });
    }

    message.isDeleted = true;
    message.text      = "This message was deleted.";
    await message.save();

    res.json({ message: "Message deleted." });
  } catch (err) {
    next(err);
  }
});


// ── Mount router ──────────────────────────────────────────────
app.use("/api", router);


// ── 404 handler ───────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ error: "Route not found." });
});


// ── Global error handler ──────────────────────────────────────
// Must have 4 parameters so Express recognises it as an error handler
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error("[ERROR]", err.stack || err.message);

  const statusCode = err.statusCode || 500;
  const message    =
    process.env.NODE_ENV === "production"
      ? "An unexpected error occurred."
      : err.message || "Internal Server Error";

  res.status(statusCode).json({ error: message });
});


// ====================== SOCKET SETUP ======================

const io = new Server(server, {
  cors: {
    origin:      CLIENT_URL,
    credentials: true,
    methods:     ["GET", "POST"],
  },
  pingTimeout:  60_000,   // Kill connection after 60 s of no ping
  pingInterval: 25_000,   // Ping every 25 s
});

// ── Socket authentication middleware ─────────────────────────
io.use(protectSocket);

// ── Typing state (in-memory, per conversation) ────────────────
// Structure: Map<conversationId, Map<userId, NodeJS.Timeout>>
// We store the debounce timer per user/conversation so it can be
// cleared when the user explicitly stops typing or disconnects.
const typingTimers = new Map();

// Helper: get or create the inner map for a conversation
const getConvTypers = (convId) => {
  if (!typingTimers.has(convId)) typingTimers.set(convId, new Map());
  return typingTimers.get(convId);
};

// ── Connection handler ────────────────────────────────────────
io.on("connection", async (socket) => {
  const user = socket.user;
  const uid  = user._id.toString();

  console.log(`🔌  Connected: ${user.name} [${socket.id}]`);

  // ── 1. Mark user online & join personal room ────────────────
  // Every user has a private room named after their userId.
  // This allows targeted notifications (e.g. new message sidebar update)
  // without iterating all sockets.
  await User.findByIdAndUpdate(uid, {
    isOnline: true,
    socketId: socket.id,
    lastSeen: new Date(),
  });

  socket.join(uid);   // Personal room

  // Broadcast presence change to everyone else
  socket.broadcast.emit("presence", {
    userId:   uid,
    isOnline: true,
  });


  // ── 2. Join a conversation room ─────────────────────────────
  // Clients call this after opening a chat window.
  // Room name: "conv:<conversationId>"
  socket.on("conv:join", async ({ conversationId }) => {
    if (!conversationId) return;

    // Verify membership before joining the room
    const conv = await Conversation.exists({
      _id:          conversationId,
      participants: uid,
    });

    if (!conv) {
      return socket.emit("error", { message: "Not a participant of this conversation." });
    }

    socket.join(`conv:${conversationId}`);
    console.log(`📬  ${user.name} joined conv:${conversationId}`);
  });


  // ── 3. Leave a conversation room ────────────────────────────
  socket.on("conv:leave", ({ conversationId }) => {
    socket.leave(`conv:${conversationId}`);
  });


  // ── 4. Send message ─────────────────────────────────────────
  // Flow: validate → save to DB → update Conversation → emit to room
  //
  // Using an acknowledgement callback so the client knows if the
  // message was persisted (important for retry logic).
  socket.on("msg:send", async ({ conversationId, text }, ack) => {
    try {
      // Validate
      if (!conversationId || !text?.trim()) {
        return ack?.({ error: "conversationId and text are required." });
      }

      const sanitizedText = xss(text.trim());
      if (sanitizedText.length > 2000) {
        return ack?.({ error: "Message too long (max 2 000 characters)." });
      }

      // Authorisation
      const conv = await Conversation.findOne({
        _id:          conversationId,
        participants: uid,
      });
      if (!conv) {
        return ack?.({ error: "Conversation not found or access denied." });
      }

      // Persist the message
      const message = await Message.create({
        conversationId,
        sender: uid,
        text:   sanitizedText,
        readBy: [],
      });

      await message.populate("sender", "_id name avatar");

      // Increment unread count for every participant except the sender
      const unreadUpdates = {};
      conv.participants.forEach((pId) => {
        const key = pId.toString();
        if (key !== uid) {
          unreadUpdates[`unreadCounts.${key}`] =
            (conv.unreadCounts?.[key] || 0) + 1;
        }
      });

      await Conversation.findByIdAndUpdate(conversationId, {
        lastMessage: message._id,
        updatedAt:   new Date(),
        $set:        unreadUpdates,
      });

      const payload = message.toObject();

      // Emit to all sockets in the conversation room
      // (this includes the sender so they get server-confirmed data)
      io.to(`conv:${conversationId}`).emit("msg:new", {
        message:        payload,
        conversationId,
      });

      // Also notify participants not currently in the room
      // so their sidebar can refresh (unread badge etc.)
      conv.participants.forEach((pId) => {
        const key = pId.toString();
        if (key !== uid) {
          io.to(key).emit("conv:updated", {
            conversationId,
            lastMessage:  payload,
            unreadCount:  unreadUpdates[`unreadCounts.${key}`],
          });
        }
      });

      // Acknowledge successful delivery to sender
      ack?.({ ok: true, message: payload });
    } catch (err) {
      console.error("[msg:send]", err.message);
      ack?.({ error: "Failed to send message. Please try again." });
    }
  });


  // ── 5. Typing indicator ──────────────────────────────────────
  // Client calls "typing:on" on every keystroke (no debouncing on
  // the client needed — the server handles it).
  //
  // Server emits "typing" to the room with isTyping: true.
  // After 2 s of silence the server auto-emits isTyping: false.
  socket.on("typing:on", ({ conversationId }) => {
    if (!conversationId) return;

    const typers = getConvTypers(conversationId);

    // Clear any existing auto-stop timer for this user
    if (typers.has(uid)) clearTimeout(typers.get(uid));

    // Notify others in the room
    socket.to(`conv:${conversationId}`).emit("typing", {
      conversationId,
      userId:    uid,
      userName:  user.name,
      isTyping:  true,
    });

    // Auto-stop after 2 s — handles the case where the user stops
    // typing without explicitly triggering "typing:off"
    const timer = setTimeout(() => {
      socket.to(`conv:${conversationId}`).emit("typing", {
        conversationId,
        userId:   uid,
        userName: user.name,
        isTyping: false,
      });
      typers.delete(uid);
      if (typers.size === 0) typingTimers.delete(conversationId);
    }, 2_000);

    typers.set(uid, timer);
  });

  socket.on("typing:off", ({ conversationId }) => {
    if (!conversationId) return;

    const typers = getConvTypers(conversationId);
    if (typers.has(uid)) {
      clearTimeout(typers.get(uid));
      typers.delete(uid);
    }

    socket.to(`conv:${conversationId}`).emit("typing", {
      conversationId,
      userId:   uid,
      userName: user.name,
      isTyping: false,
    });
  });


  // ── 6. Read receipts ─────────────────────────────────────────
  // Client emits this when the user opens (or scrolls to the bottom of)
  // a conversation, signalling that all visible messages have been read.
  socket.on("msg:read", async ({ conversationId }) => {
    try {
      if (!conversationId) return;

      // Mark all unread messages from other participants as read
      const result = await Message.updateMany(
        {
          conversationId,
          sender: { $ne: uid },
          readBy: { $ne: uid },
        },
        { $addToSet: { readBy: uid } }
      );

      if (result.modifiedCount === 0) return;  // Nothing to update

      // Reset unread counter for this user
      await Conversation.findByIdAndUpdate(conversationId, {
        $set: { [`unreadCounts.${uid}`]: 0 },
      });

      // Tell the other participants their messages have been read
      socket.to(`conv:${conversationId}`).emit("msg:read", {
        conversationId,
        readBy: uid,
        readAt: new Date(),
      });
    } catch (err) {
      console.error("[msg:read]", err.message);
    }
  });


  // ── 7. Disconnect ─────────────────────────────────────────────
  socket.on("disconnect", async (reason) => {
    console.log(`🔌  Disconnected: ${user.name} [${reason}]`);

    // Clean up any active typing timers for this user
    typingTimers.forEach((typers, convId) => {
      if (typers.has(uid)) {
        clearTimeout(typers.get(uid));
        typers.delete(uid);
        // Emit a final "stopped typing" to all rooms this user was in
        socket.to(`conv:${convId}`).emit("typing", {
          conversationId: convId,
          userId:         uid,
          userName:       user.name,
          isTyping:       false,
        });
      }
    });

    // Mark offline — check that no other socket is open for this user
    // (covers the case where a user has multiple tabs open)
    const remainingSockets = await io.in(uid).fetchSockets();
    if (remainingSockets.length === 0) {
      await User.findByIdAndUpdate(uid, {
        isOnline: false,
        lastSeen: new Date(),
        socketId: null,
      });

      socket.broadcast.emit("presence", {
        userId:   uid,
        isOnline: false,
        lastSeen: new Date(),
      });
    }
  });
});


// ====================== SERVER START ======================

server.listen(PORT, () => {
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log(`🚀  Connect API running on port ${PORT}`);
  console.log(`🌍  Accepting requests from ${CLIENT_URL}`);
  console.log(`📡  Socket.io ready`);
  console.log(`🗃️   MongoDB: ${MONGO_URI}`);
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
});

// Export for testing
module.exports = { app, server, io };