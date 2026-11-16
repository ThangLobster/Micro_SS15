package com.microservice.identity.exception;

/**
 * Bài 4 - Exception khi refresh token không hợp lệ / đã hết hạn / đã bị xoay vòng.
 * GlobalExceptionHandler sẽ map sang HTTP 403 Forbidden.
 */
public class InvalidRefreshTokenException extends RuntimeException {
    public InvalidRefreshTokenException(String message) {
        super(message);
    }
}
