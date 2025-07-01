# ZKP LAN Chat

A secure, one-to-one private chat web application for LAN, using Zero Knowledge Proofs (ZKP) for user authentication. No user data is stored on the server.

## Features
- One-to-one private chat over LAN
- User authentication using Zero Knowledge Proofs (ZKP)
- No passwords or user data stored on the server
- Modern web UI (React)

## Tech Stack
- Frontend: React
- Backend: Node.js, Express, WebSocket
- ZKP: elliptic (Schnorr protocol)
- (Optional) Encryption: [Not yet implemented—messages are sent in plaintext after authentication]

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
1. **Register:**
   - Enter a username and generate a secret (kept locally).
   - The app creates a ZKP public key/commitment.
2. **Login:**
   - Prove knowledge of your secret using ZKP (no password sent).
   - If successful, you can start a private chat with another authenticated user.
3. **Chat:**
   - Messages are currently sent in plaintext after authentication. (Encryption can be added in the future.)

## Security Explanation
- **Zero Knowledge Proof:**
  - Uses the Schnorr protocol (via elliptic) to prove knowledge of a secret without revealing it.
  - No passwords or secrets are ever sent to the server.
- **No User Data Stored:**
  - The server is stateless regarding users; all authentication is ephemeral.
- **Encryption:**
  - [Not yet implemented] Messages are currently sent in plaintext after authentication. For true end-to-end encryption, a shared secret (e.g., ECDH) should be used to encrypt/decrypt messages.

## For Developers
- See `/server` and `/client` for code.
- ZKP logic is in the main app files using the elliptic library.

## License
MIT
