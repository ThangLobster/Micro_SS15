package com.microservice.course.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Bài 3 - D. CourseController với danh sách khóa học TĨNH trong Java List (không dùng DB).
 *
 * Bài 3 (RBAC):
 *   GET  /api/courses -> hasAuthority('STUDENT') or hasAuthority('INSTRUCTOR')
 *   POST /api/courses -> hasAuthority('INSTRUCTOR')
 *
 * Bài 6 (PBAC):
 *   GET  /api/courses -> hasAuthority('COURSE_READ')
 *   POST /api/courses -> hasAuthority('COURSE_WRITE')
 */
@RestController
@RequestMapping("/api/courses")
public class CourseController {

    private final Map<Integer, String> courses = new LinkedHashMap<>();

    public CourseController() {
        courses.put(1, "Java Spring Boot Microservices");
        courses.put(2, "React Frontend Advanced");
        courses.put(3, "Database Design & Optimization");
        courses.put(4, "Docker & Kubernetes Practical");
    }

    /**
     * Bài 3 - Xem danh sách khóa học.
     * Bài 6 - đổi sang quyền cụ thể COURSE_READ.
     */
    @GetMapping
    @PreAuthorize("hasAuthority('STUDENT') or hasAuthority('INSTRUCTOR') "
            + "or hasAuthority('COURSE_READ')")
    public ResponseEntity<List<String>> getCourses() {
        return ResponseEntity.ok(new ArrayList<>(courses.values()));
    }

    /**
     * Bài 3 - Tạo khóa học mới (chỉ INSTRUCTOR).
     * Bài 6 - đổi sang quyền cụ thể COURSE_WRITE.
     */
    @PostMapping
    @PreAuthorize("hasAuthority('INSTRUCTOR') or hasAuthority('COURSE_WRITE')")
    public ResponseEntity<Map<String, Object>> createCourse(@RequestBody Map<String, Object> body) {
        String name = String.valueOf(body.getOrDefault("name", "New Course"));
        int id = courses.size() + 1;
        courses.put(id, name);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("id", id, "name", name));
    }

    /**
     * Bài 3 - Chi tiết một khóa học.
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('STUDENT') or hasAuthority('INSTRUCTOR') "
            + "or hasAuthority('COURSE_READ')")
    public ResponseEntity<Map<String, Object>> getCourse(@PathVariable int id) {
        String name = courses.get(id);
        if (name == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "Course " + id + " not found"));
        }
        return ResponseEntity.ok(Map.of("id", id, "name", name));
    }

    /**
     * Tiện ích kiểm thử: xem các Header mà Gateway truyền xuống
     * (X-User-Role, X-User-Permissions) cùng danh sách quyền đã được suy ra.
     */
    @GetMapping("/debug/authorities")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> debugAuthorities(
            @RequestHeader(value = "X-User-Id", required = false) String userId,
            @RequestHeader(value = "X-User-Role", required = false) String role,
            @RequestHeader(value = "X-User-Permissions", required = false) String permissions,
            org.springframework.security.core.Authentication authentication) {

        List<String> authorities = new ArrayList<>();
        if (authentication != null && authentication.getAuthorities() != null) {
            authentication.getAuthorities().forEach(a -> authorities.add(a.getAuthority()));
        }

        return ResponseEntity.ok(Map.of(
                "X-User-Id", userId == null ? "" : userId,
                "X-User-Role", role == null ? "" : role,
                "X-User-Permissions", permissions == null ? "" : permissions,
                "grantedAuthorities", authorities));
    }
}
