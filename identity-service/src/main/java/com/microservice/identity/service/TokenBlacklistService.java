package com.microservice.identity.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;

/**
 * Bài 5 - Quản lý Blacklist Token trong Redis.
 *
 * JWT là Stateless nên không thể thu hồi tự nhiên. Khi user Logout, ta lưu jti của token
 * vào Redis dưới key "blacklist:{jti}" kèm TTL = thời gian còn lại của token.
 * Key sẽ tự động bị Redis xoá khi token hết hạn -> không cần dọn dẹp thủ công.
 */
@Service
@RequiredArgsConstructor
public class TokenBlacklistService {

    /** Tiền tố key dùng chung với Gateway-Service. */
    public static final String BLACKLIST_PREFIX = "blacklist:";

    private final StringRedisTemplate redisTemplate;

    /**
     * Bài 5 - Ghi jti vào blacklist với TTL = exp - now.
     */
    public void blacklist(String jti, Instant expiry) {
        if (jti == null) {
            return;
        }
        Duration ttl = Duration.between(Instant.now(), expiry);
        if (ttl.isNegative() || ttl.isZero()) {
            // Token đã hết hạn -> không cần blacklist
            return;
        }
        redisTemplate.opsForValue().set(BLACKLIST_PREFIX + jti, "revoked", ttl);
    }

    public boolean isBlacklisted(String jti) {
        if (jti == null) {
            return false;
        }
        return Boolean.TRUE.equals(redisTemplate.hasKey(BLACKLIST_PREFIX + jti));
    }

    public void remove(String jti) {
        if (jti != null) {
            redisTemplate.delete(BLACKLIST_PREFIX + jti);
        }
    }
}
