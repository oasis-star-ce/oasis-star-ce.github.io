const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const crypto = require('crypto');
const { ChaCha } = require('@stablelib/chacha');
const { GridFSBucket } = require('mongodb');
const app = express();
const port = process.env.PORT || 3000;
const upload = multer({ storage: multer.memoryStorage() });

// 連接到 MongoDB Atlas
mongoose.connect(process.env.MONGODB_URI, { 
    useNewUrlParser: true, 
    useUnifiedTopology: true 
})
.then(() => console.log('Connected to MongoDB Atlas'))
.catch(err => console.error('MongoDB connection error:', err));

// 初始化 GridFS
let gfs;
mongoose.connection.once('open', () => {
    gfs = new GridFSBucket(mongoose.connection.db, { bucketName: 'files' });
});

// 定義用戶模型
const userSchema = new mongoose.Schema({
    email: String,
    username: String,
    password: String,
    secret: String,
});
const User = mongoose.model('User', userSchema);

// 定義檔案元數據模型
const fileSchema = new mongoose.Schema({
    userId: String,
    filename: String,
    gridfsId: mongoose.Schema.Types.ObjectId,
    algorithm: String,
    key: String,
    nonce: String,
});
const File = mongoose.model('File', fileSchema);

// 中間件
app.use(cors({
    origin: ['http://localhost:3000', 'https://oasis-star-ce.github.io'],
    credentials: true,
}));
app.use(bodyParser.json());
app.use(express.static(__dirname));

// JWT 驗證中間件
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid token' });
        }
        req.user = user;
        next();
    });
}

// 註冊
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
        res.status(201).json({ message: 'Registration successful', qrCodeUrl });
    } catch (err) {
        res.status(500).json({ message: 'Failed to generate QR code' });
    }
});

// 登錄
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
        window: 1,
    });

    if (!verified) {
        return res.status(401).json({ message: 'Invalid two-factor code' });
    }

    const token = jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET, {
        expiresIn: '1d',
    });

    res.status(200).json({ message: 'Login successful', token });
});

// 加密檔案
app.post('/api/encrypt', authenticateToken, upload.array('files'), async (req, res) => {
    try {
        const { algorithm } = req.body;
        if (!['AES', 'ChaCha'].includes(algorithm)) {
            return res.status(400).json({ message: 'Invalid algorithm' });
        }
        if (!req.files || req.files.length === 0) {
            return res.status(400).json({ message: 'No files uploaded' });
        }

        const userId = req.user.id;
        const key = crypto.randomBytes(32);

        for (const file of req.files) {
            let encryptedData;
            let nonce;
            if (algorithm === 'AES') {
                const iv = crypto.randomBytes(16);
                const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
                encryptedData = Buffer.concat([
                    cipher.update(file.buffer),
                    cipher.final(),
                ]);
                nonce = iv.toString('base64');
            } else if (algorithm === 'ChaCha') {
                const chachaNonce = crypto.randomBytes(12);
                const cipher = new ChaCha(key, chachaNonce);
                encryptedData = cipher.encrypt(file.buffer);
                nonce = chachaNonce.toString('base64');
            }

            const uploadStream = gfs.openUploadStream(`${file.originalname}.enc`);
            uploadStream.write(encryptedData);
            uploadStream.end();

            const gridfsId = await new Promise((resolve, reject) => {
                uploadStream.on('finish', () => resolve(uploadStream.id));
                uploadStream.on('error', reject);
            });

            await File.create({
                userId,
                filename: `${file.originalname}.enc`,
                gridfsId,
                algorithm,
                key: key.toString('base64'),
                nonce,
            });
        }

        res.json({ message: 'Files encrypted successfully' });
    } catch (error) {
        console.error('Encryption error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// 檔案列表
app.get('/api/files', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const files = await File.find({ userId });
        res.json({
            files: files.map(file => ({ name: file.filename })),
        });
    } catch (error) {
        console.error('Error fetching files:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// 下載檔案
app.get('/api/download/:filename', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const filename = req.params.filename;
        const file = await File.findOne({ userId, filename });
        if (!file) {
            return res.status(404).json({ message: 'File not found' });
        }

        const downloadStream = gfs.openDownloadStream(file.gridfsId);
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.setHeader('Content-Type', 'application/octet-stream');
        downloadStream.pipe(res);

        downloadStream.on('error', (error) => {
            console.error('Download error:', error);
            res.status(500).json({ message: 'Server error' });
        });
    } catch (error) {
        console.error('Download error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// 刪除檔案
app.delete('/api/delete/:filename', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const filename = req.params.filename;
        const file = await File.findOne({ userId, filename });
        if (!file) {
            return res.status(404).json({ message: 'File not found' });
        }

        await gfs.delete(file.gridfsId);
        await File.deleteOne({ userId, filename });

        res.json({ message: 'File deleted successfully' });
    } catch (error) {
        console.error('Delete error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Ping 端點
app.get('/api/ping', (req, res) => {
    res.status(200).json({ message: 'Ping received' });
});

// Hello 端點
app.get('/api/hello', (req, res) => {
    res.json({ message: 'Hello from the backend!' });
});

app.listen(port, '0.0.0.0', () => {
    console.log(`Server running on port ${port}`);
});
