package xyz.tcheeric.nap.core;

import java.util.List;

public record Nip98Event(
        String id,
        String pubkey,
        long createdAt,
        int kind,
        List<List<String>> tags,
        String content,
        String sig
) {
}
