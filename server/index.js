// ZKP LAN Chat Backend (Schnorr ZKP) - Multi-User Support
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Use secp256k1 curve for Schnorr ZKP
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');

// In-memory user store (in production, this would be a database)
const users = {}; // username -> { publicKey, salt }
const sessions = {};
const authenticatedUsers = {}; // username -> sessionId mapping

// Helper function to derive private key from password
function derivePrivateKey(password, salt) {
  const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
  return ec.keyFromPrivate(key, 'hex');
}

// Helper function to generate salt
function generateSalt() {
  return crypto.randomBytes(16).toString('hex');
}

// --- User Registration: create account with password ---
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  console.log(`[ZKP] Registration attempt: username=${username}`);
  
  if (!username || !password) {
    return res.status(400).json({ success: false, error: 'Missing username or password' });
  }
  
  if (users[username]) {
    return res.status(400).json({ success: false, error: 'Username already exists' });
  }
  
  if (password.length < 6) {
    return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });
  }
  
  try {
    // Generate salt and derive private key from password
    const salt = generateSalt();
    const privateKey = derivePrivateKey(password, salt);
    const publicKey = privateKey.getPublic('hex');
    
    // Store user (only public key and salt, never the private key)
    users[username] = {
      publicKey,
      salt
    };
    
    console.log(`[ZKP] User registered: username=${username}, publicKey=${publicKey}`);
    res.json({ success: true, message: 'Registration successful' });
  } catch (error) {
    console.error('[ZKP] Registration error:', error);
    res.status(500).json({ success: false, error: 'Registration failed' });
  }
});

// --- User Login: initiate ZKP authentication ---
app.post('/api/login', (req, res) => {
  const { username } = req.body;
  console.log(`[ZKP] Login attempt: username=${username}`);
  
  if (!username || !users[username]) {
    return res.status(400).json({ success: false, error: 'User not found' });
  }
  
  // Create session for ZKP authentication
  const sessionId = crypto.randomBytes(8).toString('hex');
  sessions[sessionId] = { 
    username, 
    publicKey: users[username].publicKey,
    salt: users[username].salt
  };
  
  console.log(`[ZKP] Login session created: sessionId=${sessionId}`);
  res.json({ success: true, sessionId, salt: users[username].salt });
});

// --- Challenge: server sends random challenge for ZKP ---
app.post('/api/challenge', (req, res) => {
  const { sessionId } = req.body;
  if (!sessions[sessionId]) {
    return res.status(400).json({ success: false, error: 'Invalid session' });
  }
  
  const challenge = crypto.randomBytes(32).toString('hex');
  sessions[sessionId].challenge = challenge;
  console.log(`[ZKP] Challenge issued: sessionId=${sessionId}, challenge=${challenge}`);
  res.json({ success: true, challenge });
});

// --- ZKP Proof Verification (Schnorr) ---
app.post('/api/zkp-auth', (req, res) => {
  const { sessionId, commitment, response } = req.body;
  console.log(`[ZKP] Proof received: sessionId=${sessionId}, commitment=${commitment}, response=${response}`);
  
  const session = sessions[sessionId];
  if (!session || !session.challenge) {
    return res.status(400).json({ success: false, error: 'Invalid session or challenge' });
  }
  
  try {
    // Parse public key
    const pubKey = ec.keyFromPublic(session.publicKey, 'hex').getPublic();
    // Parse commitment
    const R = ec.keyFromPublic(commitment, 'hex').getPublic();
    // Challenge as big number
    const e = ec.keyFromPrivate(session.challenge, 'hex').getPrivate();
    // Response as big number
    const s = ec.keyFromPrivate(response, 'hex').getPrivate();
    
    // Verify Schnorr proof: s*G = R + e*P
    const sG = ec.g.mul(s);
    const eP = pubKey.mul(e);
    const R_plus_eP = R.add(eP);
    const valid = sG.eq(R_plus_eP);
    
    if (valid) {
      session.authenticated = true;
      authenticatedUsers[session.username] = sessionId;
      console.log(`[ZKP] Authentication successful: username=${session.username}`);
      res.json({ success: true });
    } else {
      console.log(`[ZKP] Authentication failed: invalid proof`);
      res.status(401).json({ success: false, error: 'Invalid ZKP proof' });
    }
  } catch (error) {
    console.error('[ZKP] Proof verification error:', error);
    res.status(400).json({ success: false, error: 'Malformed proof' });
  }
});

// --- Get list of online users ---
app.get('/api/users', (req, res) => {
  const onlineUsers = Object.keys(authenticatedUsers).map(username => ({
    username,
    sessionId: authenticatedUsers[username]
  }));
  res.json({ success: true, users: onlineUsers });
});

// --- WebSocket Chat ---
const clients = {}; // sessionId -> WebSocket
const userSessions = {}; // username -> WebSocket

wss.on('connection', (ws, req) => {
  let sessionId = null;
  let username = null;

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      if (data.type === 'auth') {
        // { type: 'auth', sessionId }
        if (sessions[data.sessionId] && sessions[data.sessionId].authenticated) {
          sessionId = data.sessionId;
          username = sessions[sessionId].username;
          clients[sessionId] = ws;
          userSessions[username] = ws;
          ws.send(JSON.stringify({ type: 'auth', success: true }));
          // Notify all users about new user
          broadcastUserList();
        } else {
          ws.send(JSON.stringify({ type: 'auth', success: false }));
        }
      } else if (data.type === 'chat' && sessionId) {
        // { type: 'chat', to, message }
        const targetUsername = data.to;
        const targetWs = userSessions[targetUsername];
        if (targetWs) {
          targetWs.send(JSON.stringify({ 
            type: 'chat', 
            from: username, 
            message: data.message,
            timestamp: new Date().toISOString()
          }));
          // Send confirmation to sender
          ws.send(JSON.stringify({ 
            type: 'chat_sent', 
            to: targetUsername, 
            message: data.message,
            timestamp: new Date().toISOString()
          }));
        } else {
          ws.send(JSON.stringify({ type: 'error', error: 'User not found or offline' }));
        }
      } else if (data.type === 'get_users') {
        // Send current user list
        const onlineUsers = Object.keys(userSessions).map(name => ({
          username: name,
          sessionId: authenticatedUsers[name]
        }));
        ws.send(JSON.stringify({ type: 'user_list', users: onlineUsers }));
      }
    } catch (e) {
      ws.send(JSON.stringify({ type: 'error', error: 'Invalid message format' }));
    }
  });

  ws.on('close', () => {
    if (sessionId && clients[sessionId]) {
      delete clients[sessionId];
    }
    if (username && userSessions[username]) {
      delete userSessions[username];
      delete authenticatedUsers[username];
    }
    // Notify remaining users
    broadcastUserList();
  });
});

function broadcastUserList() {
  const onlineUsers = Object.keys(userSessions).map(name => ({
    username: name,
    sessionId: authenticatedUsers[name]
  }));
  const message = JSON.stringify({ type: 'user_list', users: onlineUsers });
  Object.values(userSessions).forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(message);
    }
  });
}

// --- Start Server ---
const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log(`ZKP LAN Chat backend running on port ${PORT}`);
}); 