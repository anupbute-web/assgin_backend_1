require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json({ limit: "128kb" })); 

mongoose
  .connect(process.env.MONGODB_URL)
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.log(err));

const userSchema = new mongoose.Schema(
  {
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
  },
  { timestamps: true },
);

const User = mongoose.model("User", userSchema);

const postSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    username: { type: String, required: true },
    text: { type: String, default: "" },
    image: { type: String, default: "" },
    likes: [{ type: String }],
    comments: [
      {
        username: String,
        text: String,
        createdAt: { type: Date, default: Date.now },
      },
    ],
  },
  { timestamps: true },
);

const Post = mongoose.model("Post", postSchema);

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  console.log(token)
  if (!token) return res.status(401).json({ message: "Access Denied" });
  try {
    const verified = jwt.verify(
      token,
      process.env.JWT_SECRET || "supersecretkey",
    );
    req.user = verified;
    next();
  } catch (err) {
    console.log(err)
    res.status(400).json({ message: "Invalid Token" });
  }
};

app.post("/api/auth/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ message: "Email already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET || "supersecretkey",
      { expiresIn: "1d" },
    );
    res
      .status(200)
      .json({
        token,
        user: { id: user._id, username: user.username, email: user.email },
      });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/posts", verifyToken, async (req, res) => {
  try {
    const { text, image } = req.body;
    if (!text && !image)
      return res.status(400).json({ message: "Post must have text or image" });

    const newPost = new Post({
      userId: req.user.id,
      username: req.user.username,
      text,
      image,
    });
    await newPost.save();
    res.status(201).json(newPost);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/posts", verifyToken, async (req, res) => {
  try {
    const posts = await Post.find().sort({ createdAt: -1 }).limit(50);
    res.status(200).json(posts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/posts/:id/like", verifyToken, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    const username = req.user.username;

    if (post.likes.includes(username)) {
      post.likes = post.likes.filter((user) => user !== username);
    } else {
      post.likes.push(username);
    }
    await post.save();
    res.status(200).json(post);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/posts/:id/comment", verifyToken, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text)
      return res.status(400).json({ message: "Comment cannot be empty" });

    const post = await Post.findById(req.params.id);
    post.comments.push({ username: req.user.username, text });
    await post.save();
    res.status(200).json(post);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(5000, () => console.log(`Server running on 5000`));
