package com.microservice.identity.exception;

/**
 * Bài 5 - Exception khi token đã bị thu hồi (blacklist) hoặc không hợp lệ.
 */
public class TokenRevokedException extends RuntimeException {
    public TokenRevokedException(String message) {
        super(message);
    }
}
