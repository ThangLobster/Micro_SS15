package com.microservice.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;

/**
 * Bài 2 - B. Parse & verify JWT tại Gateway.
 *
 * Gateway dùng CHUNG Secret Key với Identity-Service để verify chữ ký & hạn,
 * sau đó lấy role (Bài 2) và permissions (Bài 6) ra khỏi payload.
 */
@Component
public class JwtUtils {

    @Value("${app.jwt.secret}")
    private String secret;

    private Key signingKey;

    @PostConstruct
    public void init() {
        this.signingKey = buildKey(secret);
    }

    static Key buildKey(String secret) {
        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(secret);
        } catch (IllegalArgumentException e) {
            keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        }
        if (keyBytes.length < 32) {
            keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        }
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Verify chữ ký + hạn. Ném exception (ExpiredJwtException / SignatureException)
     * nếu token hết hạn hoặc sai chữ ký.
     */
    public Claims validateToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
