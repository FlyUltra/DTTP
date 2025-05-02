package cz.flyultra.server;

import cz.flyultra.nonce.NonceStore;
import cz.flyultra.utils.CryptoUtils;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;

public class SecureServer {

    private static final NonceStore nonceStore = new NonceStore();

    public static void main(String[] args) throws Exception {
        KeyPair serverKeyPair = CryptoUtils.generateECKeyPair();
        String serverFingerprint = CryptoUtils.fingerprint(serverKeyPair.getPublic());
        System.out.println("Server public key fingerprint: " + serverFingerprint);

        ServerSocket serverSocket = new ServerSocket(5000);
        Socket client = serverSocket.accept();
        BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));
        PrintWriter out = new PrintWriter(client.getOutputStream(), true);

        out.println(CryptoUtils.encodePublicKey(serverKeyPair.getPublic()));

        PublicKey clientPublicKey = CryptoUtils.decodePublicKey(in.readLine());

        SecretKey aesKey = CryptoUtils.deriveSharedSecret(serverKeyPair.getPrivate(), clientPublicKey);

        System.out.println("Encrypted connection established successfully");

        while (true) {
            String nonce = in.readLine();
            String ivLine = in.readLine();
            String encryptedLine = in.readLine();

            if (nonce == null || ivLine == null || encryptedLine == null) break;

            if (nonceStore.isUsed(nonce)) {
                System.out.println("Detected reused nonce – message ignored: " + nonce);
                continue;
            }

            nonceStore.store(nonce);

            byte[] iv = CryptoUtils.fromBase64(ivLine);
            byte[] encrypted = CryptoUtils.fromBase64(encryptedLine);
            String decrypted = new String(CryptoUtils.aesDecrypt(encrypted, aesKey, iv));

            System.out.println("Received message from client: " + decrypted);

            String responseNonce = CryptoUtils.generateNonce();
            byte[] responseIV = CryptoUtils.generateIV();
            byte[] responseEncrypted = CryptoUtils.aesEncrypt(decrypted.getBytes(), aesKey, responseIV);

            out.println(responseNonce);
            out.println(CryptoUtils.toBase64(responseIV));
            out.println(CryptoUtils.toBase64(responseEncrypted));
        }

        client.close();
        serverSocket.close();
    }
}
