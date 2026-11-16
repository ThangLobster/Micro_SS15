package com.microservice.identity.util;

import com.microservice.identity.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Bài 1 - C. Khung JwtUtil (Boilerplate) - sinh & giải mã Access Token.
 *
 * Access Token: JWT thuật toán HS256, TTL ngắn (15 phút).
 *  - Standard Claim "sub" : username
 *  - Standard Claim "jti" : JWT ID - mã định danh duy nhất của token (Bắt buộc)
 *  - Private Claim "role" : STUDENT / INSTRUCTOR (RBAC - Bài 1 & Bài 3)
 *  - Private Claim "permissions" : mảng quyền chi tiết (PBAC - Bài 6)
 *
 * Refresh Token KHÔNG phải JWT - nó là chuỗi ngẫu nhiên lưu trong DB
 * (xem RefreshTokenService).
 */
@Component
public class JwtUtils {

    @Value("${app.jwt.secret}")
    private String secret;

    @Value("${app.jwt.access-token-expiration}")
    private long accessTokenExpiration;

    private Key signingKey;

    @PostConstruct
    public void init() {
        this.signingKey = buildKey(secret);
    }

    /**
     * Hỗ trợ cả 2 dạng: secret Base64 (>= 32 byte sau decode) hoặc secret raw text.
     * Nếu không decode được Base64 thì dùng luôn bytes của chuỗi gốc.
     */
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
     * Bài 1 - C. Tạo Access Token chứa sub (username), role, permissions và jti.
     */
    public String generateAccessToken(User user) {
        Instant now = Instant.now();
        Instant expiry = now.plusMillis(accessTokenExpiration);

        return Jwts.builder()
                // Standard Claim: subject = username
                .setSubject(user.getUsername())
                // Standard Claim: jti - mã định danh duy nhất của token (bắt buộc)
                .setId(UUID.randomUUID().toString())
                // Standard Claim: thời điểm phát hành & hết hạn
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(expiry))
                // Private Claim: role (RBAC)
                .claim("role", user.getRole())
                // Private Claim: permissions (PBAC - Bài 6)
                .claim("permissions", List.copyOf(
                        user.getPermissions() == null ? List.of() : user.getPermissions()))
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Bài 5 - Giải mã token để lấy claim "jti" và "exp" (verify chữ ký + hạn).
     */
    public Claims validateToken(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            throw new RuntimeException("Token has expired", e);
        } catch (MalformedJwtException e) {
            throw new RuntimeException("Token is malformed", e);
        } catch (SignatureException e) {
            throw new RuntimeException("Invalid token signature", e);
        }
    }

    public long getAccessTokenExpiration() {
        return accessTokenExpiration;
    }
}
