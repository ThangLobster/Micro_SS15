package com.microservice.identity.repository;

import com.microservice.identity.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    /** Tìm refresh token theo chuỗi, kèm luôn User sở hữu (qua @ManyToOne EAGER). */
    Optional<RefreshToken> findByToken(String token);

    /** Bài 4 - Token Rotation: xoá bản ghi refresh token cũ. */
    void deleteByToken(String token);

    /** Bài 5 - Logout: thu hồi toàn bộ refresh token của user. */
    void deleteByUserId(UUID userId);
}
