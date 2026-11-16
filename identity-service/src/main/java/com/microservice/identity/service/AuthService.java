package com.microservice.identity.service;

import com.microservice.identity.dto.LoginRequest;
import com.microservice.identity.dto.RefreshTokenRequest;
import com.microservice.identity.dto.RegisterRequest;
import com.microservice.identity.dto.TokenResponse;
import com.microservice.identity.dto.UserResponse;
import com.microservice.identity.entity.RefreshToken;
import com.microservice.identity.entity.User;
import com.microservice.identity.exception.InvalidRefreshTokenException;
import com.microservice.identity.exception.TokenRevokedException;
import com.microservice.identity.repository.UserRepository;
import com.microservice.identity.util.JwtUtils;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Lõi nghiệp vụ xác thực của Identity-Service.
 *
 *  - Bài 1: login -> cấp cặp Access Token (JWT 15p) + Refresh Token (7 ngày, lưu DB)
 *  - Bài 4: refresh -> Token Rotation (xoá token cũ, cấp cặp mới)
 *  - Bài 5: logout -> đưa jti của access token vào blacklist Redis
 *  - Bài 6: đóng gói mảng quyền chi tiết vào Custom Claim "permissions"
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    /**
     * Bài 6 - PBAC: quyền mặc định theo role.
     * INSTRUCTOR có toàn bộ quyền, STUDENT chỉ có quyền đọc.
     */
    private static final Set<String> ALL_PERMISSIONS = Set.of(
            "COURSE_READ", "COURSE_WRITE", "COURSE_UPDATE", "COURSE_DELETE");

    private static final Set<String> STUDENT_PERMISSIONS = Set.of("COURSE_READ");

    private static final Set<String> INSTRUCTOR_PERMISSIONS = Set.of(
            "COURSE_READ", "COURSE_WRITE", "COURSE_UPDATE", "COURSE_DELETE");

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistService tokenBlacklistService;

    /**
     * Tạo tài khoản mới. Mật khẩu được băm bằng BCrypt trước khi lưu.
     */
    public UserResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username already exists");
        }

        String role = request.getRole() == null || request.getRole().isBlank()
                ? "STUDENT" : request.getRole().toUpperCase();

        // Bài 6 - nếu client chỉ định rõ permissions thì dùng, ngược lại suy ra từ role
        Set<String> permissions = request.getPermissions() != null && !request.getPermissions().isEmpty()
                ? new LinkedHashSet<>(request.getPermissions())
                : defaultPermissionsFor(role);

        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(role)
                .permissions(permissions)
                .build();

        User savedUser = userRepository.save(user);

        return UserResponse.builder()
                .id(savedUser.getId())
                .username(savedUser.getUsername())
                .role(savedUser.getRole())
                .permissions(savedUser.getPermissions())
                .build();
    }

    /**
     * Bài 1 - E. Luồng Login.
     *
     * 1. Tìm user theo username trong DB.
     * 2. So sánh mật khẩu gửi lên với mật khẩu đã băm BCrypt (passwordEncoder.matches).
     * 3. Nếu đúng -> sinh Access Token (JJWT/HS256, 15 phút, có sub/role/jti).
     * 4. Sinh Refresh Token ngẫu nhiên (7 ngày) và lưu vào bảng refresh_tokens.
     * 5. Trả về client cả cặp Access + Refresh Token.
     */
    @Transactional
    public TokenResponse login(LoginRequest request) {
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("Bad credentials"));

        // Bài 1 - so sánh mật khẩu đã băm (BCrypt)
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Bad credentials");
        }

        String accessToken = jwtUtils.generateAccessToken(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        return TokenResponse.of(accessToken, refreshToken.getToken(),
                jwtUtils.getAccessTokenExpiration());
    }

    /**
     * Bài 4 - C. API Token Rotation.
     *
     * 1. Truy vấn DB tìm bản ghi chứa refreshToken nhận lên.
     * 2. Nếu không tồn tại hoặc đã quá hạn -> ném Exception (403).
     * 3. (Rotation) Xoá hẳn bản ghi refresh token cũ -> chống sử dụng lại.
     * 4. Sinh Access Token mới + Refresh Token hoàn toàn mới, lưu refresh token mới vào DB.
     * 5. Trả cặp token mới cho client.
     */
    @Transactional
    public TokenResponse refreshToken(RefreshTokenRequest request) {
        // 1. Truy vấn Database
        RefreshToken storedToken = refreshTokenService.findByToken(request.getRefreshToken())
                .orElseThrow(() -> new InvalidRefreshTokenException("Refresh token not found"));

        // 2. Kiểm tra hạn
        if (refreshTokenService.verifyExpiration(storedToken)) {
            refreshTokenService.deleteByToken(storedToken);
            throw new InvalidRefreshTokenException("Refresh token has expired");
        }

        if (storedToken.isRevoked()) {
            throw new InvalidRefreshTokenException("Refresh token has been revoked");
        }

        User user = storedToken.getUser();

        // 3. (QUAN TRỌNG - ROTATION) Xoá bản ghi refresh token cũ khỏi DB
        refreshTokenService.deleteByToken(storedToken);

        // 4. Sinh access token mới
        String accessToken = jwtUtils.generateAccessToken(user);

        // 5. Sinh refresh token hoàn toàn mới và lưu DB
        RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(user);

        // 6. Trả cặp token mới
        return TokenResponse.of(accessToken, newRefreshToken.getToken(),
                jwtUtils.getAccessTokenExpiration());
    }

    /**
     * Bài 5 - C. API Logout.
     *
     * 1. Giải mã access token để lấy claim "jti" và "exp".
     * 2. Tính TTL = thời gian hết hạn còn lại.
     * 3. Lưu key "blacklist:{jti}" vào Redis với value "revoked" và TTL đúng bằng TTL còn lại.
     * 4. (Tuỳ chọn) Thu hồi luôn refresh token tương ứng trong PostgreSQL.
     */
    @Transactional
    public void logout(String token) {
        Claims claims = jwtUtils.validateToken(token);
        String jti = claims.getId();
        Instant expiry = claims.getExpiration() != null
                ? claims.getExpiration().toInstant()
                : Instant.now().plusMillis(jwtUtils.getAccessTokenExpiration());

        // 1-3: ghi jti vào blacklist Redis kèm TTL = thời gian còn lại của token
        tokenBlacklistService.blacklist(jti, expiry);

        // 4: thu hồi refresh token của user
        User user = userRepository.findByUsername(claims.getSubject()).orElse(null);
        if (user != null) {
            refreshTokenService.revokeAllForUser(user.getId());
        }
    }

    /**
     * Bài 5 - Kiểm tra access token có bị thu hồi (blacklist) hay không.
     */
    public void assertNotRevoked(String token) {
        Claims claims = jwtUtils.validateToken(token);
        if (tokenBlacklistService.isBlacklisted(claims.getId())) {
            throw new TokenRevokedException("Token has been revoked");
        }
    }

    public User getUserByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found: " + username));
    }

    /**
     * Bài 6 - Suy ra quyền chi tiết từ role.
     */
    private Set<String> defaultPermissionsFor(String role) {
        return switch (role) {
            case "INSTRUCTOR" -> INSTRUCTOR_PERMISSIONS;
            case "ADMIN" -> ALL_PERMISSIONS;
            default -> STUDENT_PERMISSIONS;
        };
    }
}
