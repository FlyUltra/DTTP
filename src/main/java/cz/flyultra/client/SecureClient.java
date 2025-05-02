package cz.flyultra.client;

import cz.flyultra.nonce.NonceStore;
import cz.flyultra.utils.CryptoUtils;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.PublicKey;
import java.util.Scanner;

public class SecureClient {

    private static final String TRUSTED_FINGERPRINT_FILE = ".trusted_server";
    private static final NonceStore nonceStore = new NonceStore();

    public static void main(String[] args) throws Exception {
        Socket socket = new Socket("localhost", 5000);
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

        PublicKey serverPublicKey = CryptoUtils.decodePublicKey(in.readLine());
        String serverFingerprint = CryptoUtils.fingerprint(serverPublicKey);

        File f = new File(TRUSTED_FINGERPRINT_FILE);
        if (f.exists()) {
            String known = new BufferedReader(new FileReader(f)).readLine();
            if (!serverFingerprint.equals(known)) {
                System.err.println("Server fingerprint does not match. Possible MITM attack.");
                socket.close();
                return;
            }
        } else {
            System.out.println("Saving new server fingerprint: " + serverFingerprint);
            PrintWriter writer = new PrintWriter(new FileWriter(f));
            writer.println(serverFingerprint);
            writer.close();
        }

        var clientKeyPair = CryptoUtils.generateECKeyPair();
        out.println(CryptoUtils.encodePublicKey(clientKeyPair.getPublic()));

        SecretKey aesKey = CryptoUtils.deriveSharedSecret(clientKeyPair.getPrivate(), serverPublicKey);
        System.out.println("Encrypted connection established successfully");

        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.print("Message: ");
            String msg = scanner.nextLine();
            String nonce = CryptoUtils.generateNonce();
            byte[] iv = CryptoUtils.generateIV();
            byte[] encrypted = CryptoUtils.aesEncrypt(msg.getBytes(), aesKey, iv);

            out.println(nonce);
            out.println(CryptoUtils.toBase64(iv));
            out.println(CryptoUtils.toBase64(encrypted));

            String responseNonce = in.readLine();
            String responseIV = in.readLine();
            String responseEncrypted = in.readLine();

            if (responseNonce == null || responseIV == null || responseEncrypted == null) break;

            if (nonceStore.isUsed(responseNonce)) {
                System.out.println("Detected reused nonce from server. Ignoring message: " + responseNonce);
                continue;
            }

            nonceStore.store(responseNonce);

            byte[] rIV = CryptoUtils.fromBase64(responseIV);
            byte[] rEncrypted = CryptoUtils.fromBase64(responseEncrypted);
            String response = new String(CryptoUtils.aesDecrypt(rEncrypted, aesKey, rIV));

            System.out.println("Server response: " + response);
        }

        socket.close();
    }
}