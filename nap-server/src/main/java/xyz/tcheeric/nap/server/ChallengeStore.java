package xyz.tcheeric.nap.server;

import xyz.tcheeric.nap.core.ChallengeRecord;

import java.util.Optional;

public interface ChallengeStore {

    void create(ChallengeRecord record);

    Optional<ChallengeRecord> get(String challengeId);

    RedeemResult redeem(String challengeId, RedeemParams params);

    int markExpired(long nowUnix);
}
