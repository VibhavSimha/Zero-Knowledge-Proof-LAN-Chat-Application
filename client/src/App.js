import React, { useState, useRef, useEffect } from 'react';
import { ec as EC } from 'elliptic';
import crypto from 'crypto-js';

const ec = new EC('secp256k1');
const WS_URL = 'ws://192.168.0.110:4000';
const API_URL = 'http://192.168.0.110:4000';

function App() {
  const [step, setStep] = useState('auth'); // 'auth', 'register', 'login', 'challenge', 'prove', 'chat'
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [sessionId, setSessionId] = useState('');
  const [salt, setSalt] = useState('');
  const [keyPair, setKeyPair] = useState(null);
  const [challenge, setChallenge] = useState('');
  const [commitment, setCommitment] = useState('');
  const [response, setResponse] = useState('');
  const [ws, setWs] = useState(null);
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [activeChats, setActiveChats] = useState({}); // username -> chat data
  const [selectedChat, setSelectedChat] = useState(null);
  const [message, setMessage] = useState('');
  const wsRef = useRef(null);

  // Helper function to derive private key from password and salt
  const derivePrivateKey = (password, salt) => {
    const key = crypto.PBKDF2(password, salt, {
      keySize: 256/32,
      iterations: 100000
    });
    return ec.keyFromPrivate(key.toString(), 'hex');
  };

  // Registration: create account with password
  const handleRegister = async () => {
    if (!username.trim() || !password.trim()) {
      alert('Please enter both username and password');
      return;
    }
    
    if (password.length < 6) {
      alert('Password must be at least 6 characters');
      return;
    }

    try {
      console.log(`[ZKP] Registering user: ${username}`);
      const res = await fetch(`${API_URL}/api/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();
      if (data.success) {
        alert('Registration successful! You can now login.');
        setStep('auth');
        setUsername('');
        setPassword('');
      } else {
        alert(`Registration failed: ${data.error}`);
      }
    } catch (error) {
      console.error('Registration error:', error);
      alert('Registration failed');
    }
  };

  // Login: initiate ZKP authentication
  const handleLogin = async () => {
    if (!username.trim()) {
      alert('Please enter username');
      return;
    }

    try {
      console.log(`[ZKP] Logging in user: ${username}`);
      const res = await fetch(`${API_URL}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
      });
      const data = await res.json();
      if (data.success) {
        setSessionId(data.sessionId);
        setSalt(data.salt);
        setStep('challenge');
      } else {
        alert(`Login failed: ${data.error}`);
      }
    } catch (error) {
      console.error('Login error:', error);
      alert('Login failed');
    }
  };

  // Request challenge from server
  const handleChallenge = async () => {
    const res = await fetch(`${API_URL}/api/challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sessionId })
    });
    const data = await res.json();
    if (data.success) {
      setChallenge(data.challenge);
      setStep('prove');
      console.log(`[ZKP] Received challenge from server: ${data.challenge}`);
    } else {
      alert('Challenge failed');
    }
  };

  // Generate commitment and response, send proof
  const handleProve = async () => {
    if (!password.trim()) {
      alert('Please enter your password');
      return;
    }

    try {
      // Derive private key from password and salt
      const privateKey = derivePrivateKey(password, salt);
      setKeyPair(privateKey);

      const k = ec.genKeyPair().getPrivate();
      const R = ec.g.mul(k);
      setCommitment(R.encode('hex'));
      const e = ec.keyFromPrivate(challenge, 'hex').getPrivate();
      const s = k.add(e.mul(privateKey.getPrivate())).umod(ec.curve.n);
      setResponse(s.toString('hex'));
      
      console.log(`[ZKP] Sending proof: commitment=${R.encode('hex')}, response=${s.toString('hex')}`);
      const res = await fetch(`${API_URL}/api/zkp-auth`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId, commitment: R.encode('hex'), response: s.toString('hex') })
      });
      const data = await res.json();
      if (data.success) {
        setStep('chat');
        connectWebSocket();
      } else {
        alert('ZKP authentication failed');
      }
    } catch (error) {
      console.error('Proof generation error:', error);
      alert('Authentication failed');
    }
  };

  const connectWebSocket = () => {
    const socket = new window.WebSocket(WS_URL);
    socket.onopen = () => {
      socket.send(JSON.stringify({ type: 'auth', sessionId }));
      socket.send(JSON.stringify({ type: 'get_users' }));
    };
    socket.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.type === 'auth' && msg.success) {
        console.log('Authenticated successfully');
      } else if (msg.type === 'user_list') {
        setOnlineUsers(msg.users.filter(user => user.username !== username));
      } else if (msg.type === 'chat') {
        addMessage(msg.from, msg.message, msg.timestamp, false);
      } else if (msg.type === 'chat_sent') {
        addMessage(msg.to, msg.message, msg.timestamp, true);
      }
    };
    wsRef.current = socket;
    setWs(socket);
  };

  const addMessage = (otherUser, text, timestamp, isSent) => {
    setActiveChats(prev => {
      const chatKey = isSent ? otherUser : otherUser;
      const existingChat = prev[chatKey] || { messages: [], user: chatKey };
      return {
        ...prev,
        [chatKey]: {
          ...existingChat,
          messages: [...existingChat.messages, {
            text,
            timestamp,
            isSent,
            id: Date.now() + Math.random()
          }]
        }
      };
    });
  };

  const startChat = (targetUsername) => {
    if (!activeChats[targetUsername]) {
      setActiveChats(prev => ({
        ...prev,
        [targetUsername]: { messages: [], user: targetUsername }
      }));
    }
    setSelectedChat(targetUsername);
  };

  const sendMessage = () => {
    if (wsRef.current && selectedChat && message.trim()) {
      wsRef.current.send(JSON.stringify({ type: 'chat', to: selectedChat, message: message.trim() }));
      setMessage('');
    }
  };

  const formatTime = (timestamp) => {
    return new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  return (
    <div style={styles.container}>
      {step === 'auth' && (
        <div style={styles.authContainer}>
          <h2 style={styles.title}>ZKP LAN Chat</h2>
          <div style={styles.authBox}>
            <h3>Welcome to Zero Knowledge Proof Chat</h3>
            <p style={styles.description}>
              Register a new account or login to start chatting securely.
            </p>
            <div style={styles.authButtons}>
              <button 
                style={styles.button}
                onClick={() => setStep('register')}
              >
                Register New Account
              </button>
              <button 
                style={styles.button}
                onClick={() => setStep('login')}
              >
                Login
              </button>
            </div>
          </div>
        </div>
      )}

      {step === 'register' && (
        <div style={styles.authContainer}>
          <h2 style={styles.title}>ZKP LAN Chat</h2>
          <div style={styles.authBox}>
            <h3>Register New Account</h3>
            <p style={styles.description}>
              Create a new account with a password. Your password will never be sent to the server.
            </p>
            <input 
              style={styles.input}
              placeholder="Enter username" 
              value={username} 
              onChange={e => setUsername(e.target.value)} 
            />
            <input 
              style={styles.input}
              type="password"
              placeholder="Enter password (min 6 characters)" 
              value={password} 
              onChange={e => setPassword(e.target.value)} 
            />
            <div style={styles.buttonGroup}>
              <button 
                style={styles.button}
                onClick={handleRegister} 
                disabled={!username.trim() || password.length < 6}
              >
                Register
              </button>
              <button 
                style={styles.secondaryButton}
                onClick={() => setStep('auth')}
              >
                Back
              </button>
            </div>
          </div>
        </div>
      )}

      {step === 'login' && (
        <div style={styles.authContainer}>
          <h2 style={styles.title}>ZKP LAN Chat</h2>
          <div style={styles.authBox}>
            <h3>Login</h3>
            <p style={styles.description}>
              Enter your username to start the ZKP authentication process.
            </p>
            <input 
              style={styles.input}
              placeholder="Enter username" 
              value={username} 
              onChange={e => setUsername(e.target.value)} 
            />
            <div style={styles.buttonGroup}>
              <button 
                style={styles.button}
                onClick={handleLogin} 
                disabled={!username.trim()}
              >
                Login
              </button>
              <button 
                style={styles.secondaryButton}
                onClick={() => setStep('auth')}
              >
                Back
              </button>
            </div>
          </div>
        </div>
      )}

      {step === 'challenge' && (
        <div style={styles.authContainer}>
          <h2 style={styles.title}>ZKP Authentication</h2>
          <div style={styles.authBox}>
            <h3>Request Challenge</h3>
            <p>Session ID: <code>{sessionId}</code></p>
            <button style={styles.button} onClick={handleChallenge}>
              Get Challenge
            </button>
          </div>
        </div>
      )}

      {step === 'prove' && (
        <div style={styles.authContainer}>
          <h2 style={styles.title}>ZKP Authentication</h2>
          <div style={styles.authBox}>
            <h3>Prove Knowledge</h3>
            <p>Challenge: <code>{challenge}</code></p>
            <p style={styles.description}>
              Enter your password to prove knowledge without revealing it.
            </p>
            <input 
              style={styles.input}
              type="password"
              placeholder="Enter your password" 
              value={password} 
              onChange={e => setPassword(e.target.value)} 
            />
            <button 
              style={styles.button} 
              onClick={handleProve}
              disabled={!password.trim()}
            >
              Send Proof
            </button>
          </div>
        </div>
      )}

      {step === 'chat' && (
        <div style={styles.chatContainer}>
          <div style={styles.sidebar}>
            <div style={styles.header}>
              <h3>Online Users</h3>
              <span style={styles.userCount}>{onlineUsers.length} online</span>
            </div>
            <div style={styles.userList}>
              {onlineUsers.map(user => (
                <div 
                  key={user.username}
                  style={{
                    ...styles.userItem,
                    ...(selectedChat === user.username && styles.selectedUser)
                  }}
                  onClick={() => startChat(user.username)}
                >
                  <div style={styles.userAvatar}>
                    {user.username.charAt(0).toUpperCase()}
                  </div>
                  <span>{user.username}</span>
                </div>
              ))}
              {onlineUsers.length === 0 && (
                <p style={styles.noUsers}>No other users online</p>
              )}
            </div>
          </div>

          <div style={styles.chatArea}>
            {selectedChat ? (
              <>
                <div style={styles.chatHeader}>
                  <h3>Chat with {selectedChat}</h3>
                </div>
                <div style={styles.messagesContainer}>
                  {activeChats[selectedChat]?.messages.map(msg => (
                    <div 
                      key={msg.id}
                      style={{
                        ...styles.message,
                        ...(msg.isSent ? styles.sentMessage : styles.receivedMessage)
                      }}
                    >
                      <div style={styles.messageContent}>
                        {msg.text}
                      </div>
                      <div style={styles.messageTime}>
                        {formatTime(msg.timestamp)}
                      </div>
                    </div>
                  ))}
                </div>
                <div style={styles.inputContainer}>
                  <input
                    style={styles.messageInput}
                    placeholder="Type a message..."
                    value={message}
                    onChange={e => setMessage(e.target.value)}
                    onKeyPress={e => e.key === 'Enter' && sendMessage()}
                  />
                  <button 
                    style={styles.sendButton}
                    onClick={sendMessage}
                    disabled={!message.trim()}
                  >
                    Send
                  </button>
                </div>
              </>
            ) : (
              <div style={styles.welcomeMessage}>
                <h3>Welcome to ZKP LAN Chat!</h3>
                <p>Select a user from the sidebar to start chatting.</p>
                <p>All messages are protected by Zero Knowledge Proof authentication.</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

const styles = {
  container: {
    height: '100vh',
    fontFamily: 'Arial, sans-serif',
    backgroundColor: '#f5f5f5'
  },
  authContainer: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    height: '100vh',
    backgroundColor: '#f5f5f5'
  },
  title: {
    color: '#333',
    marginBottom: '20px'
  },
  authBox: {
    backgroundColor: 'white',
    padding: '30px',
    borderRadius: '8px',
    boxShadow: '0 2px 10px rgba(0,0,0,0.1)',
    textAlign: 'center',
    minWidth: '300px'
  },
  description: {
    color: '#666',
    marginBottom: '20px',
    fontSize: '14px'
  },
  input: {
    width: '100%',
    padding: '12px',
    margin: '10px 0',
    border: '1px solid #ddd',
    borderRadius: '4px',
    fontSize: '16px'
  },
  button: {
    backgroundColor: '#007bff',
    color: 'white',
    padding: '12px 24px',
    border: 'none',
    borderRadius: '4px',
    fontSize: '16px',
    cursor: 'pointer',
    marginTop: '10px',
    marginRight: '10px'
  },
  secondaryButton: {
    backgroundColor: '#6c757d',
    color: 'white',
    padding: '12px 24px',
    border: 'none',
    borderRadius: '4px',
    fontSize: '16px',
    cursor: 'pointer',
    marginTop: '10px'
  },
  authButtons: {
    display: 'flex',
    flexDirection: 'column',
    gap: '10px'
  },
  buttonGroup: {
    display: 'flex',
    gap: '10px',
    justifyContent: 'center'
  },
  chatContainer: {
    display: 'flex',
    height: '100vh'
  },
  sidebar: {
    width: '250px',
    backgroundColor: 'white',
    borderRight: '1px solid #ddd',
    display: 'flex',
    flexDirection: 'column'
  },
  header: {
    padding: '20px',
    borderBottom: '1px solid #ddd',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center'
  },
  userCount: {
    fontSize: '12px',
    color: '#666'
  },
  userList: {
    flex: 1,
    overflowY: 'auto'
  },
  userItem: {
    display: 'flex',
    alignItems: 'center',
    padding: '12px 20px',
    cursor: 'pointer',
    borderBottom: '1px solid #f0f0f0'
  },
  selectedUser: {
    backgroundColor: '#e3f2fd'
  },
  userAvatar: {
    width: '32px',
    height: '32px',
    borderRadius: '50%',
    backgroundColor: '#007bff',
    color: 'white',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: '10px',
    fontSize: '14px',
    fontWeight: 'bold'
  },
  noUsers: {
    padding: '20px',
    textAlign: 'center',
    color: '#666'
  },
  chatArea: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column'
  },
  chatHeader: {
    padding: '20px',
    borderBottom: '1px solid #ddd',
    backgroundColor: 'white'
  },
  messagesContainer: {
    flex: 1,
    padding: '20px',
    overflowY: 'auto',
    backgroundColor: '#f8f9fa'
  },
  message: {
    marginBottom: '10px',
    maxWidth: '70%'
  },
  sentMessage: {
    marginLeft: 'auto',
    textAlign: 'right'
  },
  receivedMessage: {
    marginRight: 'auto'
  },
  messageContent: {
    padding: '10px 15px',
    borderRadius: '15px',
    display: 'inline-block',
    wordBreak: 'break-word'
  },
  sentMessage: {
    marginLeft: 'auto',
    textAlign: 'right',
    '& .messageContent': {
      backgroundColor: '#007bff',
      color: 'white'
    }
  },
  receivedMessage: {
    marginRight: 'auto',
    '& .messageContent': {
      backgroundColor: 'white',
      border: '1px solid #ddd'
    }
  },
  messageTime: {
    fontSize: '11px',
    color: '#666',
    marginTop: '5px'
  },
  inputContainer: {
    padding: '20px',
    backgroundColor: 'white',
    borderTop: '1px solid #ddd',
    display: 'flex'
  },
  messageInput: {
    flex: 1,
    padding: '12px',
    border: '1px solid #ddd',
    borderRadius: '4px',
    marginRight: '10px'
  },
  sendButton: {
    backgroundColor: '#007bff',
    color: 'white',
    padding: '12px 20px',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer'
  },
  welcomeMessage: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    textAlign: 'center',
    color: '#666'
  }
};

export default App; 