package com.microservice.identity.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Bài 1 - E. DTO trả về cho Client chứa CẢ HAI loại token.
 *
 * - accessToken  : JWT (HS256) sống 15 phút, chứa sub / role / permissions / jti
 * - refreshToken : chuỗi ngẫu nhiên sống 7 ngày, lưu trong bảng refresh_tokens
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenResponse {

    /** JWT ngắn hạn (15 phút) dùng để gọi API. */
    private String accessToken;

    /** Chuỗi UUID dài hạn (7 ngày) dùng để lấy access token mới. */
    private String refreshToken;

    /** Loại token, luôn là "Bearer". */
    @Builder.Default
    private String tokenType = "Bearer";

    /** Thời gian hết hạn của access token (epoch millis). */
    private Long expiresIn;

    public static TokenResponse of(String accessToken, String refreshToken, long expiresIn) {
        return TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(expiresIn)
                .build();
    }
}
