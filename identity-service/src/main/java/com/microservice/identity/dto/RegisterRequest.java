package com.microservice.identity.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Bài 1 - D. Request body cho API POST /api/auth/register
 *
 * Bài 6 - cho phép chỉ định danh sách quyền chi tiết (permissions).
 * Nếu không truyền thì quyền được suy ra mặc định từ role.
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {
    private String username;
    private String password;
    private String role;
    private java.util.List<String> permissions;
}
