package xyz.tcheeric.nap.server;

import xyz.tcheeric.nap.core.AclDecision;

public interface AclResolver {

    AclDecision resolve(String npub, String pubkey);
}
