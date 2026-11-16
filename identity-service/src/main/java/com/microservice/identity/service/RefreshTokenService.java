package com.microservice.identity.service;

import com.microservice.identity.entity.RefreshToken;
import com.microservice.identity.entity.User;
import com.microservice.identity.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Bài 1 - D. Quản lý vòng đời của Refresh Token trong DB.
 *
 *  - createRefreshToken(user): sinh chuỗi ngẫu nhiên, tính expiryDate (7 ngày), lưu DB.
 *  - verifyExpiration(token)  : kiểm tra token đã quá hạn chưa.
 *
 * Bài 4 - hỗ trợ Token Rotation: xoá bản ghi refresh token cũ khi đã dùng.
 */
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${app.jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    /**
     * Bài 1 - D. Sinh refresh token mới cho user và lưu xuống DB.
     */
    @Transactional
    public RefreshToken createRefreshToken(User user) {
        String token = UUID.randomUUID().toString();
        Instant expiryDate = Instant.now().plusMillis(refreshTokenExpiration);

        RefreshToken refreshToken = RefreshToken.builder()
                .token(token)
                .expiryDate(expiryDate)
                .user(user)
                .revoked(false)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    /**
     * Bài 1 - D. Kiểm tra refresh token đã quá hạn chưa.
     */
    public boolean verifyExpiration(RefreshToken refreshToken) {
        if (refreshToken == null || refreshToken.getExpiryDate() == null) {
            return true;
        }
        return refreshToken.getExpiryDate().isBefore(Instant.now());
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    /**
     * Bài 4 - Token Rotation: xoá hẳn refresh token cũ khỏi DB.
     */
    @Transactional
    public void deleteByToken(RefreshToken refreshToken) {
        refreshTokenRepository.delete(refreshToken);
    }

    /**
     * Bài 5 - Logout: thu hồi toàn bộ refresh token của user.
     */
    @Transactional
    public void revokeAllForUser(UUID userId) {
        refreshTokenRepository.deleteByUserId(userId);
    }
}
