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

// In-memory session store (ephemeral, not persistent)
const sessions = {};
const authenticatedUsers = {}; // username -> sessionId mapping

// --- Registration: receive public key for session ---
app.post('/api/register', (req, res) => {
  const { username, publicKey } = req.body;
  console.log(`[ZKP] Registration: username=${username}, publicKey=${publicKey}`);
  if (!publicKey || !username) return res.status(400).json({ success: false, error: 'Missing publicKey or username' });
  const sessionId = crypto.randomBytes(8).toString('hex');
  sessions[sessionId] = { username, publicKey };
  res.json({ success: true, sessionId });
});

// --- Challenge: server sends random challenge for ZKP ---
app.post('/api/challenge', (req, res) => {
  const { sessionId } = req.body;
  if (!sessions[sessionId]) return res.status(400).json({ success: false, error: 'Invalid session' });
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
  if (!session || !session.challenge) return res.status(400).json({ success: false, error: 'Invalid session or challenge' });
  try {
    // Parse public key
    const pubKey = ec.keyFromPublic(session.publicKey, 'hex').getPublic();
    // Parse commitment
    const R = ec.keyFromPublic(commitment, 'hex').getPublic();
    // Challenge as big number
    const e = ec.keyFromPrivate(session.challenge, 'hex').getPrivate();
    // Response as big number
    const s = ec.keyFromPrivate(response, 'hex').getPrivate();
    // s*G = R + e*P
    const sG = ec.g.mul(s);
    const eP = pubKey.mul(e);
    const R_plus_eP = R.add(eP);
    const valid = sG.eq(R_plus_eP);
    if (valid) {
      session.authenticated = true;
      authenticatedUsers[session.username] = sessionId;
      res.json({ success: true });
    } else {
      res.status(401).json({ success: false, error: 'Invalid ZKP proof' });
    }
  } catch (e) {
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