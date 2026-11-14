package fr.xephi.authme.service;

import org.junit.jupiter.api.Test;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

/** Tests the connection-bound, atomic one-shot authentication gate. */
class PremiumLoginVerifierTest {

    private static final String CONNECTION = "127.0.0.1:50000";
    private final PremiumLoginVerifier verifier =
        new PremiumLoginVerifier(mock(MojangApiService.class), mock(BukkitService.class));

    @Test
    void shouldConsumeVerifiedUuidOnlyOnce() {
        UUID mojangUuid = UUID.randomUUID();
        verifier.storeVerified(CONNECTION, "Notch", mojangUuid);
        assertThat(verifier.peekVerifiedUuid("notch"), equalTo(mojangUuid));
        assertThat(verifier.consumeVerifiedUuidForConnection(CONNECTION, "NOTCH"), equalTo(mojangUuid));
        assertThat(verifier.peekVerifiedUuid("Notch"), nullValue());
        assertThat(verifier.consumeVerifiedUuidForConnection(CONNECTION, "Notch"), nullValue());
    }

    @Test
    void shouldRejectOtherConnectionWithoutConsumingProof() {
        UUID mojangUuid = UUID.randomUUID();
        verifier.storeVerified(CONNECTION, "Notch", mojangUuid);
        assertThat(verifier.consumeVerifiedUuidForConnection("127.0.0.1:50001", "notch"), nullValue());
        assertThat(verifier.consumeVerifiedUuidForConnection(null, "Notch"), nullValue());
        assertThat(verifier.consumeVerifiedUuidForConnection(CONNECTION, "NOTCH"), equalTo(mojangUuid));
    }

    @Test
    void shouldRejectUnboundSessionForBackendLogin() {
        UUID mojangUuid = UUID.randomUUID();
        verifier.storeVerified("Notch", mojangUuid);
        assertThat(verifier.peekVerifiedUuid("notch"), equalTo(mojangUuid));
        assertThat(verifier.consumeVerifiedUuidForConnection(CONNECTION, "Notch"), nullValue());
    }

    @Test
    void shouldInvalidateEarlierVerificationWhenNewConnectionStartsVerifying() {
        verifier.storeVerified(CONNECTION, "Notch", UUID.randomUUID());
        verifier.startVerification("127.0.0.1:50001", "notch", null);
        assertThat(verifier.peekVerifiedUuid("Notch"), nullValue());
    }

    @Test
    void shouldRemoveVerification() {
        verifier.storeVerified(CONNECTION, "Notch", UUID.randomUUID());
        verifier.removeVerified("NOTCH");
        assertThat(verifier.peekVerifiedUuid("Notch"), nullValue());
    }

    @Test
    void shouldReturnProofToOnlyOneConcurrentConsumer() throws Exception {
        var executor = Executors.newFixedThreadPool(2);
        try {
            for (int round = 0; round < 100; round++) {
                UUID mojangUuid = UUID.randomUUID();
                verifier.storeVerified(CONNECTION, "Notch", mojangUuid);
                CountDownLatch ready = new CountDownLatch(2);
                CountDownLatch start = new CountDownLatch(1);
                java.util.concurrent.Callable<UUID> consume = () -> {
                    ready.countDown();
                    if (!start.await(5, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("Concurrent gate test did not start");
                    }
                    return verifier.consumeVerifiedUuidForConnection(CONNECTION, "Notch");
                };
                var first = executor.submit(consume);
                var second = executor.submit(consume);
                assertTrue(ready.await(5, TimeUnit.SECONDS));
                start.countDown();
                UUID a = first.get(5, TimeUnit.SECONDS);
                UUID b = second.get(5, TimeUnit.SECONDS);
                assertTrue((mojangUuid.equals(a) && b == null) || (mojangUuid.equals(b) && a == null),
                    "Exactly one connection-bound consumer must receive the proof");
            }
        } finally {
            executor.shutdownNow();
        }
    }
}
