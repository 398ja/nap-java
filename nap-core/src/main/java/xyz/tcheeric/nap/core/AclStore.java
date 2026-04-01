package xyz.tcheeric.nap.core;

import java.util.Optional;

public interface AclStore {

    Optional<AclRecord> findByPubkey(String appId, String pubkey);

    void create(AclRecord record);
}
