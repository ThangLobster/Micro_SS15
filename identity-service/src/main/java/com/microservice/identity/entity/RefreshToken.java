package com.microservice.identity.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

/**
 * Bài 1 - A. Thiết kế Database (Persistence Layer)
 *
 * Lưu trữ Refresh Token xuống PostgreSQL:
 *  - id         : UUID khoá chính
 *  - token      : chuỗi ngẫu nhiên duy nhất (UUID.randomUUID())
 *  - expiryDate : thời điểm hết hạn của refresh token (7 ngày)
 *  - user       : quan hệ ManyToOne tới User (owner của token)
 *  - revoked    : đánh dấu token đã bị thu hồi (Bài 4 - Token Rotation / Logout)
 *
 * Dùng FetchType.EAGER cho quan hệ user để có thể lấy thông tin User sở hữu
 * refresh token ngay trong 1 lần truy vấn.
 */
@Entity
@Table(name = "refresh_tokens", indexes = {
        @Index(name = "idx_refresh_tokens_token", columnList = "token", unique = true)
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true, length = 255)
    private String token;

    @Column(name = "expiry_date", nullable = false)
    private Instant expiryDate;

    @ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "user_id", nullable = false, foreignKey = @ForeignKey(name = "fk_refresh_token_user"))
    private User user;

    /** Bài 4 - Token đã bị thu hồi (xoay vòng hoặc logout). */
    @Column(name = "revoked", nullable = false)
    @Builder.Default
    private boolean revoked = false;

    public boolean isExpired() {
        return expiryDate != null && expiryDate.isBefore(Instant.now());
    }
}
