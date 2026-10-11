package com.example.mbff;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class WhitelistTest {
    private final Whitelist wl = new Whitelist(new MobileBffProperties("t", List.of(), "", "/mobile", null, null, null,
            List.of(new MobileBffProperties.Rule(List.of("GET"), "/api/orders", List.of()),
                    new MobileBffProperties.Rule(List.of("GET"), "/api/orders/*", List.of("id")))));

    @Test void allowsListed() {
        assertTrue(wl.match("GET", "/api/orders").isPresent());
        assertTrue(wl.match("GET", "/api/orders/7").isPresent());
    }

    @Test void deniesByDefault() {
        assertTrue(wl.match("POST", "/api/orders").isEmpty());
        assertTrue(wl.match("GET", "/api/admin/users").isEmpty());
        assertTrue(wl.match("GET", "/api/orders/7/x").isEmpty());
    }

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
