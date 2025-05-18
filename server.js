const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname));

const users = [];

app.post('/api/register', async (req, res) => {
  const { email, username, password } = req.body;

  if (!email || !username || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  if (users.some(u => u.username === username)) {
    return res.status(409).json({ message: 'Username already exists' });
  }

  // 生成 TOTP 密鑰
  const secret = speakeasy.generateSecret({ length: 20, name: `OasisStar:${username}` });
  users.push({ email, username, password, secret: secret.base32 });

  // 生成 QR Code URL
  try {
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
    res.status(201).json({ message: 'Registration successful', qrCodeUrl, secret: secret.base32 });
  } catch (err) {
    res.status(500).json({ message: 'Failed to generate QR code' });
  }
});

app.post('/api/login', (req, res) => {
  const { username, password, code } = req.body;

  if (!username || !password || !code) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  const user = users.find(u => u.username === username);
  if (!user || user.password !== password) {
    return res.status(401).json({ message: 'Invalid username or password' });
  }

  // 驗證 TOTP 碼
  const verified = speakeasy.totp.verify({
    secret: user.secret,
    encoding: 'base32',
    token: code,
    window: 1 // 允許 30 秒的時間偏差
  });

  if (!verified) {
    return res.status(401).json({ message: 'Invalid two-factor code' });
  }

  res.status(200).json({ message: 'Login successful' });
});

app.get('/api/hello', (req, res) => {
  res.json({ message: 'Hello from the backend!' });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
