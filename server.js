require('dotenv').config(); // Load environment variables
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cookieParser = require('cookie-parser');
const WebSocket = require('ws');
const { v4: uuidv4 } = require('uuid');

//const clientURL = 'https://sourabhnarwal.github.io'; // Replace with your client's URL
const clientURL = process.env.CLIENT_URL || 'http://localhost:5173'; // Replace with your client's URL
const PORT = process.env.PORT || 8000;
const JWT_SECRET = process.env.JWT_SECRET;
const MONGO_URI = process.env.MONGO_URI|| "mongodb://localhost:27017/newgentalk"; // Replace with your MongoDB URI
const EMAIL_USER = process.env.SENDER_EMAIL; // Replace with your email
const EMAIL_PASS = process.env.SENDER_PASS; // Replace with your email password
const isProduction = process.env.NODE_ENV === "production";

// MongoDB Models
const User = mongoose.model(
  "User",
  new mongoose.Schema({
    gender: String,
    email: { type: String, unique: true },
    password: String,
    isVerified: { type: Boolean, default: false },
    otp: String,
  })
);

// Express App
const app = express();
app.use(cors({ origin: clientURL, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', clientURL); // Replace with your client's origin
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Expose-Headers', 'Set-Cookie');
  next();
});

const wss = new WebSocket.Server({ noServer: true });
const rooms = {}; // Manage rooms
let isolatedPeers = []; // Track isolated peers

// MongoDB Connection
mongoose.connect(MONGO_URI)
  .then(() => {
    console.log('MongoDB connected successfully');
  })
  .catch((err) => {
    console.error('MongoDB connection error:', err);
  });

// Nodemailer Transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: EMAIL_USER, pass: EMAIL_PASS },
});

// Generate OTP
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// Routes
app.post("/signup", async (req, res) => {
  const { gender, email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = generateOTP();

    const user = await User.findOne({ email });     // Check if user already exists
    if (user) return res.status(400).json({ message: "User already exists." });

    await new User({ gender, email, password: hashedPassword, otp }).save();

    // Send OTP email
    await transporter.sendMail({
      from: EMAIL_USER,
      to: email,
      subject: "Verify Your Email",
      text: `Your OTP is: ${otp}`,
    });

    res.status(200).json({ message: "User registered. Check your email for OTP." });
  } catch (error) {
    //console.log(error);
    if (User.findOne({ email })) {
      User.findOne({ email }).deleteOne();
    }
    res.status(400).json({ message: "Error creating user", error });
  }
});

app.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) return res.status(404).json({ message: "User not found." });

    if (user.otp === otp) {
      user.isVerified = true;
      user.otp = null; // Clear OTP after verification
      await user.save();
      const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: "1h" });
      res.cookie("token", token, {httpOnly: true,
        secure: isProduction, // Use HTTPS only in production
        sameSite: isProduction ? "None" : "Lax", // Adjust based on environment
        path: "/",
        maxAge: 2* 60 * 60 * 1000,
      }).status(200).json({ message: "Login successful." });
      //res.status(200).json({ message: "User verified successfully." });
    } else {
      res.status(400).json({ message: "Invalid OTP" });
    }
  } catch (error) {
    res.status(400).json({ message: "Error verifying OTP", error });
  }
});

app.post("/resend-otp", async (req, res) => {
  const { email } = req.body;
  const otp = generateOTP();
  try {
    const user = await User.findOne({ email });
    user.otp = otp;
    await user.save();
    await transporter.sendMail({
      from: EMAIL_USER,
      to: email,
      subject: "Verify Your Email",
      text: `Your OTP is: ${otp}`,
    });
    res.status(200).json({ message: "OTP resent successfully." });
  } catch (error) {
    res.status(400).json({ message: "Error resending OTP", error });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  //console.log(email);
  try {
    const user = await User.findOne({ email });
    //console.log('user:', user);
    if (!user) return res.status(404).json({ message: "User not found" });
    if (!user.isVerified) {
      await transporter.sendMail({
        from: EMAIL_USER,
        to: email,
        subject: "Verify Your Email",
        text: `Your OTP is: ${user.otp}`,
      });
      return res.status(403).json({ message: "Email not verified" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(404).json({ message: "Incorrect credentials" });

    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: "1h" });
  
    res.cookie("token", token, {httpOnly: true,
      secure: isProduction, // Use HTTPS only in production
      sameSite: isProduction ? "None" : "Lax", // Adjust based on environment
      path: "/",
      maxAge: 2*60*60*1000,
    }).status(200).json({ message: "Login successful." });
  } catch (error) {
    res.status(400).json({ message: "Error logging in", error });
  }
});

app.post('/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // Ensure secure is true in production
    sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
    path: '/',
  });
  res.status(200).json({ message: 'Logout successful.' });
});

app.post('/forgot-password', async (req, res) => {
  const { email, password } = req.body;
  const otp = generateOTP();
  const hashedPassword = await bcrypt.hash(password, 10);
  //console.log('forgot password',email);
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });
    user.otp = otp; user.password = hashedPassword; user.isVerified = false;
    await user.save();
    await transporter.sendMail({
      from: EMAIL_USER,
      to: email,
      subject: "Verify Your Email",
      text: `Your OTP is: ${otp}`,
    });
    res.status(200).json({ message: "Check your email for OTP." });
  } catch (error) {
    res.status(400).json({ message: "Error resetting password", error });
  }
});

// Middleware for Authentication
const authenticate = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Token invalid or expired." });
    req.user = user;
    next();
  });
};

// Protected Route Example
app.get("/chatroom", authenticate, (req, res) => {
  res.status(200).json({ message: "Welcome to the chatroom." });
});

wss.on('connection', (ws) => {
  //console.log('New client connected');

  ws.on('message', (message) => {
    const data = JSON.parse(message);

    switch (data.type) {
      case 'join':
        handleJoin(ws);
        break;

      case 'offer':
      case 'answer':
      case 'ice-candidate':
        forwardMessage(data, ws);
        break;

      case 'leave':
        handleLeave(ws);
        break;

      default:
        console.log(`Unknown message type: ${data.type}`);
    }
  });

  ws.on('close', () => {
    handleLeave(ws);
  });
});

function handleJoin(ws) {
  // if (jwt.verify(token, JWT_SECRET)) {
  //   console.log('Token verified');
  // }
  // else {
  //   console.log('Token not verified');
  //   ws.send(
  //     JSON.stringify({
  //       type: 'error',
  //       message: 'Authentication failed. Please log in again.',
  //     })
  //   );
  //   ws.close(); // Close the connection if token validation fails
  //   return;
  // }
  // First, check if there's an isolated peer to connect with
  if (isolatedPeers.length > 0) {
    const peer = isolatedPeers.shift();
    const newRoom = uuidv4();
    rooms[newRoom] = [peer, ws];

    peer.roomId = newRoom;
    ws.roomId = newRoom;

    // Notify both peers to start the connection
    [peer, ws].forEach((peerSocket, index) => {
      peerSocket.send(
        JSON.stringify({
          type: 'peer-ready',
          peerId: newRoom,
          isInitiator: index === 0,
        })
      );
    });

    console.log(`Created new room for isolated peers: ${newRoom}`);
    return;
  }

  // Otherwise, add to a new or existing room
  const roomId = Object.keys(rooms).find((room) => rooms[room].length < 2);
  const assignedRoom = roomId || uuidv4();

  if (!rooms[assignedRoom]) {
    rooms[assignedRoom] = [];
  }

  rooms[assignedRoom].push(ws);
  ws.roomId = assignedRoom;

  console.log(`Client joined room: ${assignedRoom}`);

  // Notify peers if room is full
  if (rooms[assignedRoom].length === 2) {
    rooms[assignedRoom].forEach((peer, index) => {
      peer.send(
        JSON.stringify({
          type: 'peer-ready',
          peerId: assignedRoom,
          isInitiator: index === 0,
        })
      );
    });
  }
}

function forwardMessage(data, ws) {
  const room = rooms[ws.roomId];
  if (room) {
    room.forEach((peer) => {
      if (peer !== ws) {
        peer.send(JSON.stringify(data));
      }
    });
  }
}

function handleLeave(ws) {
  if (isolatedPeers.includes(ws)) {
    isolatedPeers = isolatedPeers.filter((peer) => peer !== ws);
   // console.log(`Peer removed from isolated list: ${ws}`);
    return;
  }
  if (!ws.roomId) {
   // console.log('Client left without joining a room');
    return;
  }
  const roomId = ws.roomId;

  if (roomId && rooms[roomId]) {
    rooms[roomId] = rooms[roomId].filter((peer) => peer !== ws);

    if (rooms[roomId].length === 0) {
      // If the room is empty, delete it
      delete rooms[roomId];
    } else if (rooms[roomId].length === 1) {
      // If one peer is left, add them to the isolated peers list
      const remainingPeer = rooms[roomId][0];
      isolatedPeers.push(remainingPeer);
      delete rooms[roomId];
      //console.log(`Peer moved to isolated list: ${remainingPeer}`);
      // Notify the other peer about the disconnection 
      remainingPeer.send(
        JSON.stringify(
          { type: 'peer-disconnected', }
        )
      );

    }
    //console.log(`Client left room: ${roomId}`);
  }
}

// HTTP & WebSocket Server
const server = app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

server.on("upgrade", (request, socket, head) => {
  wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit("connection", ws, request);
  });
});