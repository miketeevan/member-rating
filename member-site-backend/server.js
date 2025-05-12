require('dotenv').config();
const express = require('express');
const multer = require('multer');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const JWT_SECRET = process.env.JWT_SECRET;

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  bio: { type: String, default: '' },
  avatar: { type: String, default: '' }
});

const imageSchema = new mongoose.Schema({
  filename: String,
  ratings: [{ userId: mongoose.Schema.Types.ObjectId, score: Number }],
  userId: mongoose.Schema.Types.ObjectId,
});

const User = mongoose.model('User', userSchema);
const Image = mongoose.model('Image', imageSchema);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
});

const upload = multer({ storage });

const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).send('Access Denied');
  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).send('Invalid Token');
  }
};

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashedPassword });
  await user.save();
  res.status(201).send('User registered');
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).send('Invalid credentials');
  }
  const token = jwt.sign({ _id: user._id }, JWT_SECRET);
  res.json({ token });
});

app.get('/api/users', async (req, res) => {
  const users = await User.find({}, '_id username');
  res.json(users);
});

app.get('/api/users/:id', async (req, res) => {
  const user = await User.findById(req.params.id, '-password');
  if (!user) return res.status(404).send('User not found');
  res.json(user);
});

app.put('/api/users/profile', authenticate, async (req, res) => {
  const { bio, avatar } = req.body;
  const user = await User.findById(req.user._id);
  if (!user) return res.status(404).send('User not found');
  user.bio = bio ?? user.bio;
  user.avatar = avatar ?? user.avatar;
  await user.save();
  res.json({ message: 'Profile updated', user });
});

app.get('/api/images', async (req, res) => {
  const images = await Image.find();
  res.json(images);
});

app.post('/api/images', authenticate, upload.single('image'), async (req, res) => {
  const image = new Image({ filename: req.file.filename, ratings: [], userId: req.user._id });
  await image.save();
  res.json(image);
});

app.delete('/api/images/:id', authenticate, async (req, res) => {
  const image = await Image.findById(req.params.id);
  if (!image) return res.status(404).send('Image not found');
  if (image.userId.toString() !== req.user._id) return res.status(403).send('Unauthorized');
  await Image.findByIdAndDelete(req.params.id);
  res.sendStatus(204);
});

app.post('/api/images/:id/rate', authenticate, async (req, res) => {
  const { score } = req.body;
  const image = await Image.findById(req.params.id);
  if (!image) return res.status(404).send('Image not found');
  if (image.userId.toString() === req.user._id) return res.status(403).send('Cannot rate your own image');
  if (image.ratings.some(r => r.userId.toString() === req.user._id)) return res.status(403).send('You have already rated this image');
  image.ratings.push({ userId: req.user._id, score });
  await image.save();
  res.json(image);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
