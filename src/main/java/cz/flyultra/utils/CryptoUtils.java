package cz.flyultra.utils;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

public class CryptoUtils {

    public static final int AES_KEY_SIZE = 128;
    public static final int GCM_TAG_LENGTH = 128;
    public static final int GCM_IV_LENGTH = 12;

    public static final String EC_CURVE = "secp256r1";

    public static KeyPair generateECKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec(EC_CURVE));
        return keyGen.generateKeyPair();
    }

    public static SecretKey deriveSharedSecret(PrivateKey ownPrivate, PublicKey peerPublic) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(ownPrivate);
        ka.doPhase(peerPublic, true);
        byte[] sharedSecret = ka.generateSecret();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hashed = sha256.digest(sharedSecret);
        return new SecretKeySpec(Arrays.copyOf(hashed, AES_KEY_SIZE / 8), "AES");
    }

    public static byte[] aesEncrypt(byte[] plaintext, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        return cipher.doFinal(plaintext);
    }

    public static byte[] aesDecrypt(byte[] ciphertext, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(ciphertext);
    }

    public static byte[] generateIV() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public static String toBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] fromBase64(String data) {
        return Base64.getDecoder().decode(data);
    }

    public static PublicKey decodePublicKey(String base64) throws Exception {
        byte[] bytes = fromBase64(base64);
        KeyFactory factory = KeyFactory.getInstance("EC");
        return factory.generatePublic(new X509EncodedKeySpec(bytes));
    }

    public static String encodePublicKey(PublicKey key) {
        return toBase64(key.getEncoded());
    }

    public static String fingerprint(PublicKey key) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(key.getEncoded());
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static String generateNonce() {
        return UUID.randomUUID().toString();
    }
}