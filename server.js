require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const redis = require('redis');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());

const redisClient = redis.createClient({ url: process.env.REDIS_URL || 'redis://localhost:6379' });
redisClient.connect().catch(console.error);

// Dummy user for demo
const user = {
  id: 1,
  username: 'username',
  password: 'password',
};

// Models
class Account {
  constructor(id, username, password) {
    this.id = id;
    this.username = username;
    this.password = password;
  }
}

class Task {
  constructor(title, createdBy) {
    this.title = title;
    this.created_by = createdBy;
    this.created_at = new Date();
  }
}

// Generate token
async function generateSessionTokens(userId) {
  const accessId = uuidv4();
  const refreshId = `${accessId}++${userId}`;
  const atExpires = Date.now() + 15 * 60 * 1000;
  const rtExpires = Date.now() + 7 * 24 * 60 * 60 * 1000;

  const accessToken = jwt.sign(
    { authorized: true, token_id: accessId, user_id: userId },
    process.env.ACCESS_SECRET,
    { expiresIn: '15m' }
  );

  const refreshToken = jwt.sign(
    { token_id: refreshId, user_id: userId },
    process.env.REFRESH_SECRET,
    { expiresIn: '7d' }
  );

  return {
    accessToken,
    refreshToken,
    accessId,
    refreshId,
    atExpires,
    rtExpires,
  };
}

// Store session in Redis
async function storeSession(userId, tokens) {
  await redisClient.set(tokens.accessId, userId, {
    EX: Math.floor((tokens.atExpires - Date.now()) / 1000),
  });
  await redisClient.set(tokens.refreshId, userId, {
    EX: Math.floor((tokens.rtExpires - Date.now()) / 1000),
  });
}

// Middleware
async function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(403).json({ message: 'Missing token' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.ACCESS_SECRET);
    const storedUserId = await redisClient.get(decoded.token_id);
    if (!storedUserId || parseInt(storedUserId) !== decoded.user_id) {
      return res.status(401).json({ message: 'Invalid session' });
    }
    req.user = { id: decoded.user_id, tokenId: decoded.token_id };
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Token error', error: err.message });
  }
}

// Routes
app.post('/auth/signin', async (req, res) => {
  const { username, password } = req.body;
  if (username !== user.username || password !== user.password) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const tokens = await generateSessionTokens(user.id);
  await storeSession(user.id, tokens);

  res.json({
    access_token: tokens.accessToken,
    refresh_token: tokens.refreshToken,
  });
});

app.post('/tasks/new', verifyToken, (req, res) => {
  const task = new Task(req.body.title, req.user.id);
  res.status(201).json(task);
});

app.post('/auth/signout', verifyToken, async (req, res) => {
  const accessId = req.user.tokenId;
  const refreshId = `${accessId}++${req.user.id}`;
  await redisClient.del(accessId);
  await redisClient.del(refreshId);
  res.json({ message: 'Logged out successfully' });
});

app.post('/auth/token', async (req, res) => {
  const { refresh_token } = req.body;
  if (!refresh_token) return res.status(400).json({ message: 'Missing refresh token' });

  try {
    const decoded = jwt.verify(refresh_token, process.env.REFRESH_SECRET);
    const refreshId = decoded.token_id;
    const userId = decoded.user_id;

    const stored = await redisClient.get(refreshId);
    if (!stored || parseInt(stored) !== userId) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    await redisClient.del(refreshId);
    const newTokens = await generateSessionTokens(userId);
    await storeSession(userId, newTokens);

    res.status(201).json({
      access_token: newTokens.accessToken,
      refresh_token: newTokens.refreshToken,
    });
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired refresh token' });
  }
});

// Start server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
