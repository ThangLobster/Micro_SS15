package com.microservice.gateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Bài 2 - C. Global Filter "Trạm gác biên phòng" tại API Gateway.
 *
 * Luồng xử lý:
 *  1. Lấy JWT từ Header "Authorization: Bearer &lt;token&gt;".
 *  2. Verify chữ ký + hạn bằng secret key CHUNG với Identity-Service.
 *  3. Nếu token hết hạn / sai chữ ký / thiếu -> trả về 401 Unauthorized ngay.
 *  4. Bài 5: hỏi Redis xem jti của token có nằm trong blacklist không -> nếu có thì 401.
 *  5. Bài 2: gắn Header "X-User-Role" (role từ payload).
 *  6. Bài 6: gắn Header "X-User-Permissions" (mảng quyền dạng JSON string).
 *  7. Forward request xuống service nội bộ.
 */
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    /** Tiền tố key blacklist - phải giống hệt Identity-Service. */
    private static final String BLACKLIST_PREFIX = "blacklist:";

    /** Các endpoint public không cần token. */
    private static final List<String> PUBLIC_PATTERNS = List.of(
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/refresh");

    private final JwtUtils jwtUtils;
    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public JwtAuthenticationFilter(JwtUtils jwtUtils, ReactiveRedisTemplate<String, String> redisTemplate) {
        this.jwtUtils = jwtUtils;
        this.redisTemplate = redisTemplate;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        // 0. Endpoint public -> đi thẳng xuống service, không check token
        for (String pattern : PUBLIC_PATTERNS) {
            if (pathMatcher.match(pattern, path)) {
                return chain.filter(exchange);
            }
        }

        // 1. Lấy token từ Header Authorization
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return onError(exchange, "Missing or invalid Authorization header");
        }
        String token = authHeader.substring(7);

        // 2 & 3. Verify chữ ký + hạn. Token hết hạn hoặc sai chữ ký -> 401
        Claims claims;
        try {
            claims = jwtUtils.validateToken(token);
        } catch (Exception e) {
            return onError(exchange, "Invalid or expired token");
        }

        String jti = claims.getId();

        // 4. Bài 5 - kiểm tra blacklist Redis (trước khi forward)
        return redisTemplate.hasKey(BLACKLIST_PREFIX + jti)
                .defaultIfEmpty(Boolean.FALSE)
                .flatMap(isBlacklisted -> {
                    if (Boolean.TRUE.equals(isBlacklisted)) {
                        return onError(exchange, "Token has been revoked (blacklisted)");
                    }
                    return forwardWithHeaders(exchange, chain, claims);
                });
    }

    /**
     * 5 & 6. Gắn header quyền rồi forward xuống service nội bộ.
     */
    private Mono<Void> forwardWithHeaders(ServerWebExchange exchange, GatewayFilterChain chain, Claims claims) {
        String username = claims.getSubject();
        String role = claims.get("role", String.class);

        // Bài 6 - serialize mảng permissions thành chuỗi JSON
        Object rawPermissions = claims.get("permissions");
        List<String> permissions = toStringList(rawPermissions);
        String permissionsJson = serialize(permissions);

        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header("X-User-Id", username != null ? username : "")
                // Bài 2 - role truyền xuống Course-Service
                .header("X-User-Role", role != null ? role : "")
                // Bài 6 - danh sách quyền chi tiết truyền xuống Course-Service
                .header("X-User-Permissions", permissionsJson)
                .build();

        ServerWebExchange mutatedExchange = exchange.mutate()
                .request(mutatedRequest)
                .build();

        return chain.filter(mutatedExchange);
    }

    @SuppressWarnings("unchecked")
    private List<String> toStringList(Object raw) {
        if (raw instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }
        if (raw instanceof String s && !s.isBlank()) {
            return List.of(s);
        }
        return List.of();
    }

    private String serialize(List<String> permissions) {
        try {
            return objectMapper.writeValueAsString(permissions);
        } catch (Exception e) {
            return "[]";
        }
    }

    private Mono<Void> onError(ServerWebExchange exchange, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String body = "{\"error\": \"Unauthorized\", \"message\": \"" + message + "\"}";
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = response.bufferFactory().wrap(bytes);

        return response.writeWith(Mono.just(buffer));
    }

    @Override
    public int getOrder() {
        // Chạy trước các filter routing mặc định của Spring Cloud Gateway
        return -100;
    }
}
