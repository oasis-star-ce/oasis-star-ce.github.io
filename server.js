const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const mongoose = require('mongoose');
const app = express();
const port = process.env.PORT || 3000;

// 連接到 MongoDB Atlas
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB Atlas'))
  .catch(err => console.error('MongoDB connection error:', err));

// 定義用戶模型
const userSchema = new mongoose.Schema({
  email: String,
  username: String,
  password: String,
  secret: String,
});
const User = mongoose.model('User', userSchema);

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname));

app.post('/api/register', async (req, res) => {
  const { email, username, password } = req.body;

  if (!email || !username || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  const existingUser = await User.findOne({ username });
  if (existingUser) {
    return res.status(409).json({ message: 'Username already exists' });
  }

  const secret = speakeasy.generateSecret({ length: 20, name: `OasisStar:${username}` });
  const user = new User({ email, username, password, secret: secret.base32 });
  await user.save();

  try {
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
    res.status(201).json({ message: 'Registration successful', qrCodeUrl, secret: secret.base32 });
  } catch (err) {
    res.status(500).json({ message: 'Failed to generate QR code' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password, otp } = req.body;

  if (!username || !password || !otp) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  const user = await User.findOne({ username });
  if (!user || user.password !== password) {
    return res.status(401).json({ message: 'Invalid username or password' });
  }

  const verified = speakeasy.totp.verify({
    secret: user.secret,
    encoding: 'base32',
    token: otp,
    window: 1
  });

  if (!verified) {
    return res.status(401).json({ message: 'Invalid two-factor code' });
  }

  res.status(200).json({ message: 'Login successful' });
});

// 添加 ping 端點以接收定時請求
app.get('/api/ping', (req, res) => {
  res.status(200).json({ message: 'Ping received' });
});

app.get('/api/hello', (req, res) => {
  res.json({ message: 'Hello from the backend!' });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
