package com.microservice.identity.controller;

import com.microservice.identity.dto.LoginRequest;
import com.microservice.identity.dto.RefreshTokenRequest;
import com.microservice.identity.dto.RegisterRequest;
import com.microservice.identity.dto.TokenResponse;
import com.microservice.identity.dto.UserResponse;
import com.microservice.identity.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Bài 1 - E. Controller xử lý các API xác thực.
 *
 *  POST /api/auth/login    -> Bài 1: cấp cặp Access + Refresh Token
 *  POST /api/auth/register -> tạo tài khoản (tiện cho kiểm thử)
 *  POST /api/auth/refresh  -> Bài 4: Token Rotation
 *  POST /api/auth/logout   -> Bài 5: thu hồi token qua Redis blacklist
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * Bài 1 - E. Trả về DTO chứa CẢ access token và refresh token.
     */
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    /**
     * Tạo tài khoản mới (mật khẩu được băm BCrypt).
     */
    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    /**
     * Bài 4 - Cấp lại cặp token mới (Token Rotation).
     */
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refreshToken(request));
    }

    /**
     * Bài 5 - Logout: đưa jti của access token vào blacklist Redis.
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(
            @RequestHeader(value = "Authorization", required = false) String authorizationHeader) {

        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Missing or invalid Authorization header"));
        }

        authService.logout(authorizationHeader.substring(7));

        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }
}
