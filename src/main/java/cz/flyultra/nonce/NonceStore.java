package cz.flyultra.nonce;

import java.util.HashSet;
import java.util.Set;

public class NonceStore {
    private final Set<String> usedNonces = new HashSet<>();

    public synchronized boolean isUsed(String nonce) {
        return usedNonces.contains(nonce);
    }

    public synchronized void store(String nonce) {
        usedNonces.add(nonce);
    }
}