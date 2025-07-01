# ZKP LAN Chat

A secure, one-to-one private chat web application for LAN, using Zero Knowledge Proofs (ZKP) for user authentication. Users register with passwords and prove knowledge of their passwords without revealing them.

## Features
- One-to-one private chat over LAN
- User registration with password-based authentication
- Zero Knowledge Proof (ZKP) authentication using Schnorr protocol
- No passwords ever sent to the server
- Modern web UI (React)

## Tech Stack
- Frontend: React, crypto-js (for PBKDF2)
- Backend: Node.js, Express, WebSocket
- ZKP: elliptic (Schnorr protocol)
- Password Derivation: PBKDF2 with salt

## How ZKP Authentication Works

### Registration Process
1. User enters username and password
2. Client derives a private key from password using PBKDF2
3. Client generates public key from private key
4. Server stores only the public key and salt (never the password or private key)

### Login Process
1. User enters username
2. Server provides the salt for that user
3. Server sends a random challenge
4. Client derives private key from password + salt
5. Client generates Schnorr proof using the private key
6. Server verifies the proof without learning the private key

### Zero Knowledge Property
- The server never sees the user's password or private key
- The server only stores the public key and salt
- Authentication is proven through cryptographic proof
- Even if the server is compromised, passwords cannot be extracted

## Setup Instructions

### Prerequisites
- Node.js (v16+ recommended)
- npm (comes with Node.js)
- Two computers on the same LAN

### 1. Clone the repository
```
git clone <your-repo-url>
cd zkp-lan-chat
```

### 2. Install dependencies
```
cd server
npm install
cd ../client
npm install
```

### 3. Start the backend server
```
cd ../server
npm start
```

### 4. Start the frontend
```
cd ../client
npm start
```

### 5. Access the app
- Open your browser and go to `http://<server-ip>:3000` from both computers (replace `<server-ip>` with the LAN IP of the server machine).
- **Important:** In `client/src/App.js`, set the API and WebSocket URLs to use your server's LAN IP (e.g., `http://192.168.1.42:4000`), not `localhost`, for other devices to connect.

## Usage Guide

### 1. Registration
- Click "Register New Account"
- Enter a username and password (minimum 6 characters)
- The app will create your account using ZKP
- Your password is never sent to the server

### 2. Login
- Click "Login"
- Enter your username
- Enter your password when prompted
- The app will prove knowledge of your password using ZKP

### 3. Chat
- Once authenticated, you can see other online users
- Click on a user to start a private chat
- Messages are sent after ZKP authentication

## Security Features

### Zero Knowledge Proof
- **Schnorr Protocol:** Uses elliptic curve cryptography for efficient ZKP
- **Password Derivation:** PBKDF2 with 100,000 iterations and unique salt
- **No Password Transmission:** Passwords never leave the client
- **Stateless Authentication:** Each login requires a fresh proof

### Cryptographic Properties
- **Completeness:** Honest users always succeed in authentication
- **Soundness:** Dishonest users cannot authenticate without knowing the password
- **Zero-Knowledge:** Server learns nothing about the password during authentication

### Data Protection
- **No Password Storage:** Server only stores public keys and salts
- **Ephemeral Sessions:** Authentication sessions are temporary
- **No Message Encryption:** Messages are currently sent in plaintext after authentication

## For Developers

### Key Components
- **Server (`/server/index.js`):** Handles registration, login, ZKP verification, and WebSocket chat
- **Client (`/client/src/App.js`):** React app with registration, login, and chat UI
- **ZKP Implementation:** Uses elliptic library for Schnorr protocol

### API Endpoints
- `POST /api/register` - User registration with password
- `POST /api/login` - Initiate ZKP authentication
- `POST /api/challenge` - Get random challenge for ZKP
- `POST /api/zkp-auth` - Submit ZKP proof for verification

### Future Enhancements
- End-to-end message encryption using ECDH
- Persistent user storage (database)
- Multi-factor authentication
- Message history and offline support

## License
MIT
