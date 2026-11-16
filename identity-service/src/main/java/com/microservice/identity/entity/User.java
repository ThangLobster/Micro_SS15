package com.microservice.identity.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Bài 1 - A. Entity User: lưu thông tin người dùng trong PostgreSQL.
 *
 * - username : duy nhất, dùng làm Standard Claim "sub" của JWT
 * - password : mật khẩu đã băm bằng BCrypt
 * - role     : Private Claim "role" (Bài 1), ví dụ STUDENT / INSTRUCTOR
 * - permissions: tập quyền chi tiết (Bài 6 - PBAC), đóng gói vào Custom Claim "permissions"
 */
@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(unique = true, nullable = false)
    private String username;

    /** Mật khẩu đã băm BCrypt - KHÔNG BAO GIỜ trả về cho client. */
    @Column(nullable = false)
    private String password;

    /** Role thô (RBAC - Bài 1 & Bài 3): STUDENT, INSTRUCTOR, ... */
    @Column(nullable = false)
    @Builder.Default
    private String role = "STUDENT";

    /**
     * Bài 6 - PBAC: mỗi user có một tập quyền chi tiết theo từng hành động.
     * Quan hệ ManyToMany với bảng phụ user_permissions.
     */
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_permissions", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "permission", nullable = false)
    @Builder.Default
    private Set<String> permissions = new HashSet<>();
}
