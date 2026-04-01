package xyz.tcheeric.nap.server.store;

import xyz.tcheeric.nap.core.ChallengeRecord;
import xyz.tcheeric.nap.core.ChallengeState;
import xyz.tcheeric.nap.core.ChallengeStore;
import xyz.tcheeric.nap.core.RedeemParams;
import xyz.tcheeric.nap.core.RedeemResult;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory ChallengeStore for testing and single-instance deployments.
 */
public final class InMemoryChallengeStore implements ChallengeStore {

    private final ConcurrentHashMap<String, ChallengeRecord> store = new ConcurrentHashMap<>();

    @Override
    public void create(ChallengeRecord record) {
        store.put(record.challengeId(), record);
    }

    @Override
    public Optional<ChallengeRecord> get(String challengeId) {
        return Optional.ofNullable(store.get(challengeId));
    }

    @Override
    public RedeemResult redeem(String challengeId, RedeemParams params) {
        var ref = new Object() { RedeemResult result = RedeemResult.NOT_FOUND; };

        store.computeIfPresent(challengeId, (key, existing) -> {
            if (existing.state() == ChallengeState.EXPIRED || existing.expiresAt() < params.now()) {
                ref.result = RedeemResult.EXPIRED;
                return existing;
            }
            if (existing.state() != ChallengeState.ISSUED) {
                ref.result = RedeemResult.ALREADY_REDEEMED;
                return existing;
            }
            ref.result = RedeemResult.REDEEMED;
            return new ChallengeRecord(
                    existing.challengeId(), existing.challenge(), existing.npub(), existing.pubkey(),
                    existing.authUrl(), existing.authMethod(), existing.issuedAt(), existing.expiresAt(),
                    ChallengeState.REDEEMED, params.eventId(), params.sessionId(), params.resultCacheUntil()
            );
        });

        return ref.result;
    }

    @Override
    public int markExpired(long nowUnix) {
        int count = 0;
        for (var entry : store.entrySet()) {
            var record = entry.getValue();
            if (record.state() == ChallengeState.ISSUED && record.expiresAt() < nowUnix) {
                store.computeIfPresent(entry.getKey(), (key, existing) -> {
                    if (existing.state() == ChallengeState.ISSUED && existing.expiresAt() < nowUnix) {
                        return new ChallengeRecord(
                                existing.challengeId(), existing.challenge(), existing.npub(), existing.pubkey(),
                                existing.authUrl(), existing.authMethod(), existing.issuedAt(), existing.expiresAt(),
                                ChallengeState.EXPIRED, null, null, null
                        );
                    }
                    return existing;
                });
                count++;
            }
        }
        return count;
    }

    public void clear() {
        store.clear();
    }
}
