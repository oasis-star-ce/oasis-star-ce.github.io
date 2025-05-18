const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors()); // Enable CORS for cross-origin requests
app.use(bodyParser.json()); // Parse JSON bodies
app.use(express.static(__dirname)); // Serve static files

// In-memory user storage (replace with a database in production)
const users = [];

// Login endpoint
app.post('/api/login', (req, res) => {
  const { username, password, otp } = req.body;

  // Basic validation
  if (!username || !password || !otp) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  // Find user
  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(401).json({ message: 'Invalid username or password' });
  }

  // Check password
  if (user.password !== password) {
    return res.status(401).json({ message: 'Invalid username or password' });
  }

  // Check OTP (for demo purposes, assume OTP is always "123456")
  if (otp !== '123456') {
    return res.status(401).json({ message: 'Invalid two-factor code' });
  }

  res.status(200).json({ message: 'Login successful' });
});

// Register endpoint
app.post('/api/register', (req, res) => {
  const { email, username, password } = req.body;

  // Basic validation
  if (!email || !username || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  // Check if user already exists
  if (users.some(u => u.username === username)) {
    return res.status(409).json({ message: 'Username already exists' });
  }

  // Add user to in-memory storage
  users.push({ email, username, password });
  res.status(201).json({ message: 'Registration successful' });
});

// Sample API endpoint
app.get('/api/hello', (req, res) => {
  res.json({ message: 'Hello from the backend!' });
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
