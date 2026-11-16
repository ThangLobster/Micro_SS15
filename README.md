# Micro-SS15 — Xác thực & Phân quyền Microservices (JWT, RBAC, PBAC)

Bài lab gồm 6 bài tập xây dựng hệ thống microservices với Spring Boot 3.2.5, Spring Cloud Gateway,
Spring Security và thư viện JJWT 0.11.5.

## Kiến trúc

```
                 ┌──────────────────┐
   Client ──────►│  Gateway-Service │  :8899
                 │  (Global Filter) │
                 └────────┬─────────┘
                          │  X-User-Role / X-User-Permissions
            ┌─────────────┴──────────────┐
            ▼                            ▼
  ┌───────────────────┐        ┌──────────────────┐
  │ Identity-Service  │        │  Course-Service  │
  │      :8090        │        │      :8091       │
  │  PostgreSQL       │        │  (Java List tĩnh)│
  │  Redis (blacklist)│        └──────────────────┘
  └───────────────────┘
```

| Service | Port | Database | Vai trò |
|---|---|---|---|
| `identity-service` | 8090 | PostgreSQL + Redis | Cấp phát & thu hồi token (Bài 1, 4, 5, 6) |
| `gateway-service` | 8899 | — | Trạm gác biên phòng, verify JWT (Bài 2, 5, 6) |
| `course-service` | 8091 | — | Resource server, RBAC/PBAC (Bài 3, 6) |

## Chạy dự án

### 1. Khởi động hạ tầng

```bash
docker compose up -d
```

- PostgreSQL: `localhost:5434`, database `identity_db`, user/password `postgres/postgres`
- Redis: `localhost:6380`

> Cổng khác với SS14 (5433/6379) để chạy song song.

### 2. Build & chạy từng service

```bash
./gradlew build

cd identity-service && java -jar build/libs/identity-service-0.0.1-SNAPSHOT.jar
cd course-service   && java -jar build/libs/course-service-0.0.1-SNAPSHOT.jar
cd gateway-service  && java -jar build/libs/gateway-service-0.0.1-SNAPSHOT.jar
```

### 3. Tạo tài khoản test

```bash
# STUDENT chỉ có quyền COURSE_READ (Bài 6)
curl -X POST http://localhost:8090/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"student01","password":"123456","role":"STUDENT","permissions":["COURSE_READ"]}'

# INSTRUCTOR có toàn bộ quyền
curl -X POST http://localhost:8090/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"instructor01","password":"123456","role":"INSTRUCTOR"}'
```

## Mapping bài tập → mã nguồn

### Bài 1 — Cấp phát cặp Access & Refresh Token (Identity-Service)

| Yêu cầu | Vị trí |
|---|---|
| `SecurityFilterChain`: tắt CSRF, `STATELESS`, `permitAll` cho `/api/auth/login` | `identity-service/.../config/SecurityConfig.java` |
| So sánh mật khẩu với hash BCrypt trong DB | `identity-service/.../service/AuthService.java` (`login`) |
| Access Token HS256, sống 15 phút | `identity-service/.../util/JwtUtils.java` (`generateAccessToken`) |
| Payload có `sub`, `role`, `jti` | `JwtUtils.generateAccessToken` — `setSubject` / `claim("role")` / `setId` |
| Refresh Token ngẫu nhiên 7 ngày, lưu bảng `refresh_tokens` | `entity/RefreshToken.java` + `service/RefreshTokenService.java` |
| API `POST /api/auth/login` trả về cả cặp token | `controller/AuthController.java`, `dto/TokenResponse.java` |

Payload mẫu:
```json
{"sub":"student01","jti":"1f047793-d8a0-4d98-9d2c-87605190a39b",
 "iat":1794798153,"exp":1794799053,"role":"STUDENT","permissions":["COURSE_READ"]}
```

### Bài 2 — API Gateway "Trạm gác biên phòng" (Gateway-Service)

| Yêu cầu | Vị trí |
|---|---|
| Route `/api/courses/**` → Course-Service | `gateway-service/src/main/resources/application.yml` |
| Global Filter verify JWT (secret key chung) | `gateway-service/.../filter/JwtAuthenticationFilter.java` |
| Token hết hạn / sai chữ ký → **401** | `JwtAuthenticationFilter.filter` + `JwtUtils.validateToken` |
| Gắn Header `X-User-Role` trước khi forward | `JwtAuthenticationFilter.forwardWithHeaders` |

### Bài 3 — RBAC tại Resource Server (Course-Service)

| Yêu cầu | Vị trí |
|---|---|
| Đọc quyền từ Header `X-User-Role`, **không** giải mã JWT | `course-service/.../security/HeaderAuthenticationFilter.java` |
| `GET /api/courses` — `hasAuthority('STUDENT') or hasAuthority('INSTRUCTOR')` | `course-service/.../controller/CourseController.java` |
| `POST /api/courses` — `hasAuthority('INSTRUCTOR')` | `CourseController.createCourse` |
| Danh sách khóa học tĩnh bằng Java List | `CourseController.courses` |

### Bài 4 — Token Rotation (Identity-Service)

| Yêu cầu | Vị trí |
|---|---|
| API `POST /api/auth/refresh`, `permitAll()` | `controller/AuthController.java` + `config/SecurityConfig.java` |
| Truy vấn DB theo chuỗi refresh token | `AuthService.refreshToken` → `RefreshTokenService.findByToken` |
| Không tồn tại / hết hạn → ném Exception (403) | `exception/InvalidRefreshTokenException` + `exception/GlobalExceptionHandler` |
| Xoá hẳn refresh token cũ (rotation) | `AuthService.refreshToken` → `RefreshTokenService.deleteByToken` |
| Cấp access + refresh token mới | `AuthService.refreshToken` |

### Bài 5 — Đăng xuất an toàn với Redis Blacklist

| Yêu cầu | Vị trí |
|---|---|
| API `POST /api/auth/logout`, lấy `jti` + `ttl` còn lại | `controller/AuthController.logout` → `service/AuthService.logout` |
| Lưu `blacklist:{jti}` = `"revoked"`, TTL = ttl còn lại | `service/TokenBlacklistService.blacklist` |
| Gateway hỏi Redis bằng `ReactiveRedisTemplate` → 401 nếu bị thu hồi | `gateway-service/.../filter/JwtAuthenticationFilter.filter` |

### Bài 6 — Nâng cấp lên PBAC (Permission-Based)

| Yêu cầu | Vị trí |
|---|---|
| Identity đóng gói mảng quyền vào claim `permissions` | `identity-service/.../util/JwtUtils.java` |
| Gateway serialize quyền → Header `X-User-Permissions` (JSON) | `gateway-service/.../filter/JwtAuthenticationFilter.forwardWithHeaders` |
| Course-Service đọc Header `X-User-Permissions` | `course-service/.../security/HeaderAuthenticationFilter.java` |
| Custom Converter JSON → `List<GrantedAuthority>` | `course-service/.../security/PermissionsHeaderConverter.java` (đăng ký tại `config/CourseSecurityConfig.java`) |
| `@PreAuthorize` theo quyền cụ thể | `CourseController` — `hasAuthority('COURSE_READ')` / `hasAuthority('COURSE_WRITE')` |

## Kiểm thử nhanh (Postman / curl)

```bash
# 1. Login
curl -X POST http://localhost:8899/api/auth/login -H "Content-Type: application/json" \
  -d '{"username":"student01","password":"123456"}'

# 2. Xem danh sách khóa học qua Gateway -> 200 OK
curl http://localhost:8899/api/courses -H "Authorization: Bearer <accessToken>"

# 3. Tạo khóa học bằng token STUDENT -> 403 Forbidden
curl -X POST http://localhost:8899/api/courses -H "Authorization: Bearer <accessToken>" \
  -H "Content-Type: application/json" -d '{"name":"Course X"}'

# 4. Refresh token (xoay vòng) -> 200 OK
curl -X POST http://localhost:8899/api/auth/refresh -H "Content-Type: application/json" \
  -d '{"refreshToken":"<refreshToken>"}'

# 5. Dùng lại refresh token cũ -> 403 Forbidden
curl -X POST http://localhost:8899/api/auth/refresh -H "Content-Type: application/json" \
  -d '{"refreshToken":"<refreshTokenCũ>"}'

# 6. Logout -> sau đó dùng lại access token -> 401 Unauthorized
curl -X POST http://localhost:8899/api/auth/logout -H "Authorization: Bearer <accessToken>"
curl http://localhost:8899/api/courses -H "Authorization: Bearer <accessToken>"   # -> 401
```

## Cấu trúc thư mục

```
Micro-SS15/
├── docker-compose.yml          # PostgreSQL + Redis
├── settings.gradle
├── identity-service/           # Bài 1, 4, 5, 6
│   └── src/main/java/com/microservice/identity/
│       ├── config/             # SecurityConfig, JwtAuthenticationEntryPoint
│       ├── controller/         # AuthController
│       ├── dto/                # LoginRequest, TokenResponse, RefreshTokenRequest...
│       ├── entity/             # User, RefreshToken
│       ├── exception/          # GlobalExceptionHandler, InvalidRefreshTokenException
│       ├── filter/             # JwtAuthenticationFilter
│       ├── repository/         # UserRepository, RefreshTokenRepository
│       ├── service/            # AuthService, RefreshTokenService, TokenBlacklistService
│       └── util/               # JwtUtils
├── gateway-service/            # Bài 2, 5, 6
│   └── src/main/java/com/microservice/gateway/filter/
│       ├── JwtAuthenticationFilter.java   # verify + blacklist + gắn header
│       └── JwtUtils.java
└── course-service/             # Bài 3, 6
    └── src/main/java/com/microservice/course/
        ├── config/             # CourseSecurityConfig
        ├── controller/         # CourseController
        └── security/           # HeaderAuthenticationFilter, PermissionsHeaderConverter
```

## Chạy unit test

```bash
./gradlew test
```

Bao gồm 23 test: JWT claims & hạn (Identity), verify chữ ký (Gateway), converter permissions
và phân quyền 403/201 (Course), luồng token rotation end-to-end.

> **Lưu ý về đường dẫn:** nếu thư mục dự án nằm trong đường dẫn có ký tự không phải ASCII
> (ví dụ `Năm 4`), Gradle không thể load class cho test runner. Khi đó hãy tạo một junction
> tới đường dẫn ASCII và build từ đó:
> ```cmd
> mklink /J C:\dev\micro-ss15 "D:\Năm 4\...\Micro-SS15"
> cd /d C:\dev\micro-ss15 && gradle.bat test
> ```

## Cấu hình chính

Secret key dùng chung cho Identity & Gateway (`app.jwt.secret`):
```
vS6K5vH8N2zB4xR9mQ3pL1wT7yC5vH8N2zB4xR9mQ3pL1wT7yC5vH8N2z
```

| Thuộc tính | Giá trị | Ý nghĩa |
|---|---|---|
| `app.jwt.access-token-expiration` | `900000` (15 phút) | TTL access token |
| `app.jwt.refresh-token-expiration` | `604800000` (7 ngày) | TTL refresh token |
| `app.jwt.secret` | 64 ký tự | Khóa HS256 (≥ 32 byte) |
