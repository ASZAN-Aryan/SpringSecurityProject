package com.securitydemo.security.secrets;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

@Component
public class SecretManager {

    private static final Logger logger = LoggerFactory.getLogger(SecretManager.class);
    private static final int MIN_BYTES = 32;

    public record Keyring(String currentKid, Map<String, SecretKey> keys) {}

    private final Environment environment;
    private final AtomicReference<Keyring> keyring = new AtomicReference<>();

    public SecretManager(Environment environment) {
        this.environment = environment;
    }

    @PostConstruct
    void init() {
        keyring.set(buildKeyring());
        logger.info("Keyring loaded, currentKid={}", keyring.get().currentKid());
    }

    @Scheduled(fixedDelayString = "${secrets.reload-interval-ms:50000}")
    public void reloadSafely() {
        try {
            Keyring fresh = buildKeyring();
            if (!fresh.currentKid().equals(keyring.get().currentKid())) {
                keyring.set(fresh);
                logger.info("Keyring rotated, currentKid={}", fresh.currentKid());
            }
        } catch (Exception e) {
            logger.warn("Keyring reload failed, keeping current keys: {}", e.getMessage());
        }
    }

    public SecretKey currentSigningKey() {
        Keyring ring = keyring.get();
        return ring.keys().get(ring.currentKid());
    }

    public String currentKid() {
        return keyring.get().currentKid();
    }

    public SecretKey keyForVerification(String kid) {
        return kid == null ? null : keyring.get().keys().get(kid);
    }

    private Keyring buildKeyring() {
        Map<String, SecretKey> keys = new LinkedHashMap<>();

        SecretKey current = toKey(require("JWT_SECRET"));
        String currentKid = fingerprint(current.getEncoded());
        keys.put(currentKid, current);

        String previous = environment.getProperty("JWT_SECRET_PREVIOUS");
        if (previous != null && !previous.isBlank()) {
            SecretKey old = toKey(previous.trim());
            keys.putIfAbsent(fingerprint(old.getEncoded()), old);
        }
        return new Keyring(currentKid, Map.copyOf(keys));
    }

    private String require(String name) {
        String value = environment.getProperty(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Missing secret '" + name + "'");
        }
        return value.trim();
    }

    private SecretKey toKey(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < MIN_BYTES) {
            throw new IllegalStateException("Secret too short");
        }
        return new SecretKeySpec(bytes, "HmacSHA256");
    }

    // covert sh256 to 8 hex
    static String fingerprint(byte[] keyBytes) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(keyBytes);
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < 4; i++) hex.append(String.format("%02x", digest[i]));
            return hex.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}