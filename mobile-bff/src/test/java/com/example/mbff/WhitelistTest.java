package com.example.mbff;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** allowlist 매칭은 Gateway 라우트(yml)가 수행하므로 E2E(scripts/e2e.py)에서 검증. 여기서는 보조 로직만 단위 테스트. */
class WhitelistTest {
    @Test void rejectsTraversal() {
        for (String p : new String[]{"/api/orders/../admin/users", "/api//orders", "/api/orders/%2e%2e/x", "/api/orders;x=1"})
            assertFalse(Whitelist.isSafePath(p), p);
        assertTrue(Whitelist.isSafePath("/api/orders/7"));
    }

    @Test void filtersFields() throws Exception {
        byte[] out = ResponseFields.filter(new ObjectMapper(), "[{\"id\":1,\"ssn\":\"x\"}]".getBytes(), Set.of("id"));
        assertEquals("[{\"id\":1}]", new String(out));
    }
}
