package xyz.tcheeric.nap.server.acl;

import java.util.Optional;

public interface AclStore {

    Optional<AclRecord> findByPubkey(String appId, String pubkey);

    void create(AclRecord record);
}
