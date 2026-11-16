package com.microservice.course.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Bài 6 - B. Kiểm thử Custom Converter chuyển JSON -> List&lt;GrantedAuthority&gt;.
 */
class PermissionsHeaderConverterTest {

    private final PermissionsHeaderConverter converter = new PermissionsHeaderConverter();

    @Test
    void convertsJsonArrayToAuthorities() {
        Collection<GrantedAuthority> authorities =
                converter.convert("[\"COURSE_READ\",\"COURSE_WRITE\"]");

        assertEquals(2, authorities.size());
        assertTrue(authorities.stream()
                .anyMatch(a -> "COURSE_READ".equals(a.getAuthority())));
        assertTrue(authorities.stream()
                .anyMatch(a -> "COURSE_WRITE".equals(a.getAuthority())));
    }

    @Test
    void returnsEmptyForBlankHeader() {
        assertTrue(converter.convert(null).isEmpty());
        assertTrue(converter.convert("").isEmpty());
        assertTrue(converter.convert("   ").isEmpty());
    }

    @Test
    void returnsEmptyForMalformedJson() {
        assertTrue(converter.convert("not-json").isEmpty());
    }

    @Test
    void handlesEmptyJsonArray() {
        assertTrue(converter.convert("[]").isEmpty());
    }

    @Test
    void trimsWhitespace() {
        Collection<GrantedAuthority> authorities = converter.convert("[\" COURSE_READ \"]");
        List<String> names = authorities.stream().map(GrantedAuthority::getAuthority).toList();
        assertEquals(List.of("COURSE_READ"), names);
    }
}
