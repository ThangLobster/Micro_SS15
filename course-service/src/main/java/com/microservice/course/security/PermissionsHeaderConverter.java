package com.microservice.course.security;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Bài 6 - B. Custom Converter: chuyển chuỗi JSON trong Header "X-User-Permissions"
 * thành danh sách GrantedAuthority.
 *
 * Header do Gateway (Bài 6) gửi xuống có dạng: ["COURSE_READ","COURSE_WRITE"]
 * -> converter đọc ra List<String> -> map thành SimpleGrantedAuthority tương ứng.
 *
 * Đăng ký converter này trong SecurityConfig (xem CourseSecurityConfig).
 */
public class PermissionsHeaderConverter implements Converter<String, Collection<GrantedAuthority>> {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Override
    public Collection<GrantedAuthority> convert(String json) {
        Collection<GrantedAuthority> authorities = new ArrayList<>();

        if (json == null || json.isBlank()) {
            return authorities;
        }

        List<String> permissions = parse(json);

        for (String permission : permissions) {
            if (permission != null && !permission.isBlank()) {
                authorities.add(new SimpleGrantedAuthority(permission.trim()));
            }
        }

        return authorities;
    }

    private List<String> parse(String json) {
        try {
            return OBJECT_MAPPER.readValue(json, new TypeReference<List<String>>() {
            });
        } catch (Exception e) {
            // Header không phải JSON hợp lệ -> coi như rỗng, không cấp quyền nào
            return List.of();
        }
    }
}
