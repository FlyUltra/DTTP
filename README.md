## Custom Encrypted Protocol (ECDHE + AES-GCM + TOFU)

This project implements a secure custom communication protocol inspired by HTTPS, designed for use between trusted servers or clients.

---

## Features

* **AES-GCM** – modern encryption with authentication
* **ECDHE (Ephemeral Diffie-Hellman)** – perfect forward secrecy
* **TOFU (Trust On First Use)** – client validates server fingerprint
* **Nonce Protection** – prevents replay attacks
* **Simple text-based protocol** over TCP sockets

---

## Test Scenario

### 1. Build the Project

Assuming Gradle and JDK 17+:

```bash
./gradlew build
```

### 2. Run the Server

```bash
java -cp build/classes/java/main SecureServer
```

Output:

```
Server fingerprint: e3a5...ce12
Encrypted session established
```

### 3. Run the Client

```bash
java -cp build/classes/java/main SecureClient
```

First-time run:

```
Saving server fingerprint: e3a5...ce12
Encrypted session established
Message:
```

Enter a message, e.g.:

```
Message: Hello
```

Output:

```
Server: Hello
```

---

## Reset Trust

If the server's fingerprint changes (e.g., new key generated), the client will reject the connection. To reset trust:

```bash
rm .trusted_server  # or delete the file manually
```

---

## Security Overview

| Feature                   | Description                                           |
| ------------------------- | ----------------------------------------------------- |
| AES-GCM                   | Confidentiality + integrity                           |
| ECDHE                     | Forward secrecy (past messages safe if key is leaked) |
| Server fingerprint (TOFU) | Protects against MITM (after first trust)             |
| Nonce Protection          | Blocks replayed messages                              |
| Zero Trust infrastructure | No external CAs required – you control everything     |

---

## File Structure

| File                | Description                                   |
| ------------------- | --------------------------------------------- |
| `CryptoUtils.java`  | Cryptography (ECDHE, AES-GCM, fingerprinting) |
| `SecureServer.java` | Encrypted server implementation               |
| `SecureClient.java` | Encrypted client with fingerprint trust       |
| `NonceStore.java`   | Prevents replay attacks                       |

---

## Possible Improvements

*  Use JSON or binary message format
*  Add protocol layers (`type`, `payload`, `timestamp`)
*  Add message signatures (e.g., HMAC or RSA signatures)
*  Persist ECDH keypair on the server
