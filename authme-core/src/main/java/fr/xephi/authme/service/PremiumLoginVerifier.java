package fr.xephi.authme.service;

import fr.xephi.authme.ConsoleLogger;
import fr.xephi.authme.output.ConsoleLoggerFactory;

import javax.crypto.Cipher;
import javax.inject.Inject;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Performs cryptographic premium session verification.
 *
 * <p>Generates a per-server RSA key pair and drives an EncryptionRequest / EncryptionResponse
 * handshake with connecting clients so that the backend can independently verify premium identity
 * via Mojang's {@code hasJoined} session endpoint — without relying on the proxy.</p>
 *
 * <p>Thread-safety: all state maps are {@link ConcurrentHashMap}; RSA operations use a
 * per-call {@link Cipher} instance.</p>
 */
public class PremiumLoginVerifier {

    private static final long VERIFIED_TTL_MS = 60_000L;
    private static final long PENDING_TTL_MS = 30_000L;

    private final ConsoleLogger logger = ConsoleLoggerFactory.get(PremiumLoginVerifier.class);

    private final KeyPair rsaKeyPair;
    private final SecureRandom secureRandom;
    private final MojangApiService mojangApiService;
    private final BukkitService bukkitService;

    /** Keyed by connection address (ip:port). */
    private final ConcurrentHashMap<String, PendingVerification> pending = new ConcurrentHashMap<>();
    /** Keyed by lowercase username; entries expire after {@link #VERIFIED_TTL_MS}. */
    private final ConcurrentHashMap<String, VerifiedSession> verified = new ConcurrentHashMap<>();

    @Inject
    PremiumLoginVerifier(MojangApiService mojangApiService, BukkitService bukkitService) {
        this.mojangApiService = mojangApiService;
        this.bukkitService = bukkitService;
        this.secureRandom = new SecureRandom();
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(1024, secureRandom);
            this.rsaKeyPair = gen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA algorithm not available", e);
        }
    }

    /** Returns the server's RSA public key to embed in the EncryptionRequest packet. */
    public PublicKey getPublicKey() {
        return rsaKeyPair.getPublic();
    }

    /**
     * Begins a verification handshake for the given connection.
     *
     * @param playerUUID the UUID from the LOGIN_START packet (null on older protocol versions)
     * @return a freshly generated 4-byte verify token to embed in the EncryptionRequest
     */
    public byte[] startVerification(String connectionKey, String username, UUID playerUUID) {
        evictStalePendingEntries();
        byte[] verifyToken = new byte[4];
        secureRandom.nextBytes(verifyToken);
        pending.put(connectionKey, new PendingVerification(username, playerUUID, verifyToken, System.currentTimeMillis()));
        return verifyToken;
    }

    private void evictStalePendingEntries() {
        long now = System.currentTimeMillis();
        pending.entrySet().removeIf(e -> now - e.getValue().startedAt() > PENDING_TTL_MS);
    }

    /** Returns true if an in-flight verification exists for this connection. */
    public boolean hasPending(String connectionKey) {
        return pending.containsKey(connectionKey);
    }

    /** Returns the username associated with the pending verification, or {@code null}. */
    public String getPendingUsername(String connectionKey) {
        PendingVerification pend = pending.get(connectionKey);
        return pend != null ? pend.username() : null;
    }

    /** Returns the player UUID from the pending LOGIN_START packet, or {@code null}. */
    public UUID getPendingPlayerUUID(String connectionKey) {
        PendingVerification pend = pending.get(connectionKey);
        return pend != null ? pend.playerUUID() : null;
    }

    /** Removes the pending verification for the given connection. */
    public void cleanupPending(String connectionKey) {
        pending.remove(connectionKey);
    }

    /**
     * Decrypts a byte array using the server's RSA private key.
     * Used by the packet listener to decrypt the shared secret before setting up Netty
     * encryption, independently from the async Mojang check.
     */
    public byte[] decryptData(byte[] encrypted) throws GeneralSecurityException {
        return rsaDecrypt(encrypted);
    }

    /**
     * Completes a verification handshake: validates the verify token and calls Mojang's
     * {@code hasJoined} endpoint asynchronously.
     *
     * <p>The caller is responsible for RSA-decrypting {@code sharedSecret} before calling
     * this method (so that the Netty AES handlers can be installed synchronously on the
     * event-loop thread before this async operation starts).</p>
     *
     * @param connectionKey   key used in {@link #startVerification}
     * @param sharedSecret    already RSA-decrypted AES shared secret from the client
     * @param encVerifyToken  RSA-encrypted verify token from the client
     * @return a future resolving to the Mojang UUID on success, or empty on any failure
     */
    public CompletableFuture<Optional<UUID>> completeVerification(
            String connectionKey, byte[] sharedSecret, byte[] encVerifyToken) {
        PendingVerification pend = pending.remove(connectionKey);
        if (pend == null) {
            return CompletableFuture.completedFuture(Optional.empty());
        }
        CompletableFuture<Optional<UUID>> future = new CompletableFuture<>();
        bukkitService.runTaskAsynchronously(() -> {
            try {
                byte[] decryptedToken = rsaDecrypt(encVerifyToken);

                if (!Arrays.equals(decryptedToken, pend.verifyToken())) {
                    logger.warning("Verify token mismatch during premium verification for '" + pend.username() + "'");
                    future.complete(Optional.empty());
                    return;
                }

                String serverHash = computeServerHash(sharedSecret);
                future.complete(mojangApiService.hasJoined(pend.username(), serverHash));

            } catch (Exception e) {
                logger.warning("Premium session verification failed for '" + pend.username() + "': " + e.getMessage());
                future.complete(Optional.empty());
            }
        });
        return future;
    }

    /**
     * Stores a successfully verified Mojang UUID, bound to the connection that proved it.
     *
     * <p>Backend (no-proxy) callers MUST use this overload. Binding the session to the connection is
     * what stops another client from reusing it — see
     * {@link #consumeVerifiedUuidForConnection(String, String)}.
     *
     * @param connectionKey the {@code ip:port} of the connection that completed the handshake
     */
    public void storeVerified(String connectionKey, String username, UUID mojangUuid) {
        verified.put(username.toLowerCase(Locale.ROOT),
            new VerifiedSession(mojangUuid, System.currentTimeMillis(), connectionKey));
    }

    /**
     * Proxy-side variant: stores a verified session with no backend connection bound to it.
     *
     * <p>Only for the BungeeCord/Velocity modules, which run in the proxy JVM and have no backend
     * {@code ip:port}. The backend's own authentication gate rejects premium auto-login outright when
     * a proxy is configured (see {@code AsynchronousJoin#canBypassWithPremium}), so an unbound
     * session can never authenticate a backend join.
     */
    public void storeVerified(String username, UUID mojangUuid) {
        verified.put(username.toLowerCase(Locale.ROOT),
            new VerifiedSession(mojangUuid, System.currentTimeMillis(), null));
    }

    /**
     * Authentication gate: returns the Mojang-confirmed UUID only if the verified session was proved
     * by <b>this very connection</b>, then consumes it so it cannot be replayed.
     *
     * <p>This is the only lookup that may be used to grant a passwordless premium login. The
     * name-keyed {@link #peekVerifiedUuid(String)} must never be used for that: sessions live for
     * {@link #VERIFIED_TTL_MS} and a cracked client can connect under any name it likes, so a
     * name-only match would let it inherit a genuine player's verification.
     *
     * @param connectionKey the joining player's {@code ip:port}, in the same form the handshake used
     * @param username      the joining player's name
     * @return the verified Mojang UUID, or {@code null} if there is none for this exact connection
     */
    public UUID consumeVerifiedUuidForConnection(String connectionKey, String username) {
        if (connectionKey == null) {
            return null;
        }
        String key = username.toLowerCase(Locale.ROOT);
        VerifiedSession session = verified.get(key);
        if (session == null) {
            return null;
        }
        if (System.currentTimeMillis() - session.verifiedAt() > VERIFIED_TTL_MS) {
            verified.remove(key);
            return null;
        }
        if (!connectionKey.equals(session.connectionKey())) {
            logger.warning("Rejected premium auto-login for '" + username
                + "': a verified session exists but was proved by a different connection"
                + " (expected " + session.connectionKey() + ", got " + connectionKey + ")");
            return null;
        }
        verified.remove(key);
        return session.mojangUuid();
    }

    /**
     * Non-consuming, name-only lookup. <b>Not an authentication gate</b> — see
     * {@link #consumeVerifiedUuidForConnection(String, String)}.
     *
     * <p>Intended only for advisory decisions that are re-checked by the real gate afterwards, such
     * as whether to skip the pre-join dialog, and for the proxy modules' own flows.
     */
    public UUID peekVerifiedUuid(String username) {
        String key = username.toLowerCase(Locale.ROOT);
        VerifiedSession session = verified.get(key);
        if (session == null) {
            return null;
        }
        if (System.currentTimeMillis() - session.verifiedAt() > VERIFIED_TTL_MS) {
            verified.remove(key);
            return null;
        }
        return session.mojangUuid();
    }

    private byte[] rsaDecrypt(byte[] encrypted) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, rsaKeyPair.getPrivate());
        return cipher.doFinal(encrypted);
    }

    private String computeServerHash(byte[] sharedSecret) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update("".getBytes(StandardCharsets.ISO_8859_1)); // empty server ID (MC 1.7+)
        sha1.update(sharedSecret);
        sha1.update(rsaKeyPair.getPublic().getEncoded());
        // Minecraft uses two's-complement BigInteger hex (may have leading minus sign)
        return new BigInteger(sha1.digest()).toString(16);
    }

    // ---------------------------------------------------------------------------
    // Internal record types
    // ---------------------------------------------------------------------------

    record PendingVerification(String username, UUID playerUUID, byte[] verifyToken, long startedAt) {}

    /**
     * @param connectionKey the {@code ip:port} of the connection that completed the handshake, or
     *                      {@code null} for proxy-side sessions where no backend connection exists
     */
    record VerifiedSession(UUID mojangUuid, long verifiedAt, String connectionKey) {}
}
