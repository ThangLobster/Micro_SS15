package com.microservice.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Bài 2 - Kiểm thử JwtUtils tại Gateway: verify chữ ký + hạn, lấy role & permissions.
 */
class JwtUtilsTest {

    private static final String SECRET =
            "vS6K5vH8N2zB4xR9mQ3pL1wT7yC5vH8N2zB4xR9mQ3pL1wT7yC5vH8N2z";

    private JwtUtils jwtUtils;
    private Key key;

    @BeforeEach
    void setUp() {
        jwtUtils = new JwtUtils();
        ReflectionTestUtils.setField(jwtUtils, "secret", SECRET);
        jwtUtils.init();
        key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
    }

    private String buildToken(Date expiry, String role, List<String> permissions) {
        return Jwts.builder()
                .setSubject("student01")
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(new Date())
                .setExpiration(expiry)
                .claim("role", role)
                .claim("permissions", permissions)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    @Test
    void validTokenExposesRoleAndPermissions() {
        Date expiry = new Date(System.currentTimeMillis() + 900_000);
        String token = buildToken(expiry, "STUDENT", List.of("COURSE_READ"));

        Claims claims = jwtUtils.validateToken(token);
        assertEquals("student01", claims.getSubject());
        assertEquals("STUDENT", claims.get("role", String.class));
        assertNotNull(claims.getId());
    }

    @Test
    void expiredTokenIsRejected() {
        Date expiry = new Date(System.currentTimeMillis() - 60_000);
        String token = buildToken(expiry, "STUDENT", List.of("COURSE_READ"));

        assertThrows(Exception.class, () -> jwtUtils.validateToken(token));
    }

    @Test
    void tokenWithWrongSignatureIsRejected() {
        Key otherKey = Keys.hmacShaKeyFor(
                "DIFFERENT5vH8N2zB4xR9mQ3pL1wT7yC5vH8N2zB4xR9mQ3pL1wT7yC5".getBytes(StandardCharsets.UTF_8));
        String token = Jwts.builder()
                .setSubject("student01")
                .setExpiration(new Date(System.currentTimeMillis() + 900_000))
                .signWith(otherKey, SignatureAlgorithm.HS256)
                .compact();

        assertThrows(Exception.class, () -> jwtUtils.validateToken(token));
    }

    @Test
    void malformedTokenIsRejected() {
        assertThrows(Exception.class, () -> jwtUtils.validateToken("not-a-jwt"));
    }
}
