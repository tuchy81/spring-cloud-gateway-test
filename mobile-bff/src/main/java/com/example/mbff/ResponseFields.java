package com.example.mbff;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Set;

/** 응답 필드 allowlist 적용: 객체 또는 객체 배열의 최상위 필드만 남긴다. */
public final class ResponseFields {
    private ResponseFields() {}

    public static byte[] filter(ObjectMapper om, byte[] json, Set<String> allow) throws Exception {
        JsonNode root = om.readTree(json);
        return om.writeValueAsBytes(apply(om, root, allow));
    }

    private static JsonNode apply(ObjectMapper om, JsonNode n, Set<String> allow) {
        if (n.isArray()) {
            ArrayNode out = om.createArrayNode();
            n.forEach(e -> out.add(apply(om, e, allow)));
            return out;
        }
        if (n.isObject()) {
            ObjectNode out = om.createObjectNode();
            n.fields().forEachRemaining(en -> { if (allow.contains(en.getKey())) out.set(en.getKey(), en.getValue()); });
            return out;
        }
        return n;
    }
}
