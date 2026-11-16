package com.microservice.identity.util;

import com.microservice.identity.entity.User;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Bài 1 - Kiểm thử JwtUtils: payload phải chứa sub, role, jti (và permissions của Bài 6).
 */
class JwtUtilsTest {

    private JwtUtils jwtUtils;

    @BeforeEach
    void setUp() {
        jwtUtils = new JwtUtils();
        ReflectionTestUtils.setField(jwtUtils, "secret",
                "vS6K5vH8N2zB4xR9mQ3pL1wT7yC5vH8N2zB4xR9mQ3pL1wT7yC5vH8N2z");
        ReflectionTestUtils.setField(jwtUtils, "accessTokenExpiration", 900000L);
        jwtUtils.init();
    }

    private User user() {
        return User.builder()
                .id(UUID.randomUUID())
                .username("student01")
                .password("hashed")
                .role("STUDENT")
                .permissions(Set.of("COURSE_READ"))
                .build();
    }

    @Test
    void tokenContainsSubRoleAndJti() {
        String token = jwtUtils.generateAccessToken(user());
        Claims claims = jwtUtils.validateToken(token);

        assertEquals("student01", claims.getSubject());
        assertEquals("STUDENT", claims.get("role", String.class));
        assertNotNull(claims.getId());
        assertTrue(claims.getId().matches("^[0-9a-f-]{36}$"));
    }

    @Test
    void tokenContainsPermissionsClaim() {
        String token = jwtUtils.generateAccessToken(user());
        Claims claims = jwtUtils.validateToken(token);

        assertEquals(Set.of("COURSE_READ"),
                Set.copyOf((java.util.List<?>) claims.get("permissions")));
    }

    @Test
    void eachTokenHasUniqueJti() {
        String t1 = jwtUtils.generateAccessToken(user());
        String t2 = jwtUtils.generateAccessToken(user());

        assertNotEquals(jwtUtils.validateToken(t1).getId(), jwtUtils.validateToken(t2).getId());
    }

    @Test
    void tokenExpiresIn15Minutes() {
        String token = jwtUtils.generateAccessToken(user());
        Claims claims = jwtUtils.validateToken(token);

        long ttlMillis = claims.getExpiration().getTime() - claims.getIssuedAt().getTime();
        assertEquals(900000L, ttlMillis);
    }

    @Test
    void expiredTokenIsRejected() {
        jwtUtils = new JwtUtils();
        ReflectionTestUtils.setField(jwtUtils, "secret",
                "vS6K5vH8N2zB4xR9mQ3pL1wT7yC5vH8N2zB4xR9mQ3pL1wT7yC5vH8N2z");
        ReflectionTestUtils.setField(jwtUtils, "accessTokenExpiration", -1000L);
        jwtUtils.init();

        String token = jwtUtils.generateAccessToken(user());
        assertThrows(RuntimeException.class, () -> jwtUtils.validateToken(token));
    }

    @Test
    void tokenSignedWithDifferentSecretIsRejected() {
        JwtUtils other = new JwtUtils();
        ReflectionTestUtils.setField(other, "secret",
                "ZZZZ5vH8N2zB4xR9mQ3pL1wT7yC5vH8N2zB4xR9mQ3pL1wT7yC5vH8N2z");
        ReflectionTestUtils.setField(other, "accessTokenExpiration", 900000L);
        other.init();

        String token = other.generateAccessToken(user());
        assertThrows(RuntimeException.class, () -> jwtUtils.validateToken(token));
    }
}
