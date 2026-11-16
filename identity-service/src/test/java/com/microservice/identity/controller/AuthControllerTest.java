package com.microservice.identity.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.microservice.identity.dto.LoginRequest;
import com.microservice.identity.dto.RefreshTokenRequest;
import com.microservice.identity.dto.RegisterRequest;
import com.microservice.identity.dto.TokenResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Bài 1 & Bài 4 - Kiểm thử luồng login / refresh (Token Rotation).
 *
 * Dùng PostgreSQL + Redis thật (docker compose) nên test được đầy đủ
 * luồng xoay vòng refresh token.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:postgresql://localhost:5434/identity_db",
        "spring.datasource.username=postgres",
        "spring.datasource.password=postgres",
        "spring.data.redis.host=localhost",
        "spring.data.redis.port=6380"
})
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private String username;

    @BeforeEach
    void setUp() throws Exception {
        username = "test_" + System.nanoTime();

        RegisterRequest register = new RegisterRequest();
        register.setUsername(username);
        register.setPassword("123456");
        register.setRole("STUDENT");

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(register)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(username));
    }

    @Test
    void loginReturnsAccessAndRefreshToken() throws Exception {
        LoginRequest login = new LoginRequest();
        login.setUsername(username);
        login.setPassword("123456");

        String body = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(login)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(900000))
                .andReturn().getResponse().getContentAsString();

        TokenResponse response = objectMapper.readValue(body, TokenResponse.class);
        assertNotEmpty(response.getAccessToken());
    }

    @Test
    void loginWithWrongPasswordReturns401() throws Exception {
        LoginRequest login = new LoginRequest();
        login.setUsername(username);
        login.setPassword("wrong-password");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(login)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void refreshRotatesTokenAndOldOneIsRejected() throws Exception {
        // 1. Login
        LoginRequest login = new LoginRequest();
        login.setUsername(username);
        login.setPassword("123456");

        String loginBody = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(login)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        TokenResponse first = objectMapper.readValue(loginBody, TokenResponse.class);

        // 2. Dùng refresh token -> nhận cặp token MỚI
        RefreshTokenRequest refreshRequest = new RefreshTokenRequest();
        refreshRequest.setRefreshToken(first.getRefreshToken());

        String refreshBody = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andReturn().getResponse().getContentAsString();
        TokenResponse second = objectMapper.readValue(refreshBody, TokenResponse.class);

        // 3. Refresh token MỚI khác refresh token CŨ
        assertNotEquals(first.getRefreshToken(), second.getRefreshToken());
        assertNotEquals(first.getAccessToken(), second.getAccessToken());

        // 4. Dùng lại refresh token CŨ -> 403 Forbidden
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isForbidden());
    }

    @Test
    void refreshWithUnknownTokenReturns403() throws Exception {
        RefreshTokenRequest refreshRequest = new RefreshTokenRequest();
        refreshRequest.setRefreshToken("unknown-token-value");

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isForbidden());
    }

    private void assertNotEmpty(String value) {
        if (value == null || value.isBlank()) {
            throw new AssertionError("Expected non-empty value");
        }
    }

    private void assertNotEquals(Object a, Object b) {
        if (a == null ? b == null : a.equals(b)) {
            throw new AssertionError("Expected different values but both were: " + a);
        }
    }
}
