package xyz.tcheeric.nap.server;

import xyz.tcheeric.nap.core.AclDecision;

import java.util.List;

/**
 * Default ACL resolver that allows all principals.
 */
public final class AllowAllAclResolver implements AclResolver {

    @Override
    public AclDecision resolve(String npub, String pubkey) {
        return AclDecision.allowed(List.of(), List.of());
    }
}
