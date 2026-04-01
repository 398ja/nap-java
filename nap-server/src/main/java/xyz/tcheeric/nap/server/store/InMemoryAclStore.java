package xyz.tcheeric.nap.server.store;

import xyz.tcheeric.nap.core.AclRecord;
import xyz.tcheeric.nap.core.AclStore;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory AclStore for testing and single-instance deployments.
 */
public final class InMemoryAclStore implements AclStore {

    private final ConcurrentHashMap<String, AclRecord> store = new ConcurrentHashMap<>();

    private static String key(String appId, String pubkey) {
        return appId + ":" + pubkey;
    }

    @Override
    public Optional<AclRecord> findByPubkey(String appId, String pubkey) {
        return Optional.ofNullable(store.get(key(appId, pubkey)));
    }

    @Override
    public void create(AclRecord record) {
        store.putIfAbsent(key(record.appId(), record.pubkey()), record);
    }

    public void clear() {
        store.clear();
    }
}
