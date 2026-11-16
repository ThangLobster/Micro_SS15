package com.microservice.course.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Bài 3 - B. Filter đọc quyền TRỰC TIẾP từ Header do Gateway truyền xuống.
 *
 * Course-Service KHÔNG nhúng thư viện giải mã JWT (không cần jjwt, không cần secret key).
 * Gateway đã kiểm tra token rồi chuyển thông tin quyền qua Header:
 *
 *   X-User-Role        : "STUDENT" | "INSTRUCTOR"          (RBAC - Bài 3)
 *   X-User-Permissions : ["COURSE_READ","COURSE_WRITE"]   (PBAC - Bài 6)
 *
 * Filter này chuyển các header trên thành danh sách GrantedAuthority:
 *  - role        -> SimpleGrantedAuthority("STUDENT")     -> hasAuthority('STUDENT')
 *  - permissions -> SimpleGrantedAuthority("COURSE_READ") -> hasAuthority('COURSE_READ')
 */
@Component
public class HeaderAuthenticationFilter extends OncePerRequestFilter {

    public static final String ROLE_HEADER = "X-User-Role";
    public static final String PERMISSIONS_HEADER = "X-User-Permissions";
    public static final String USER_ID_HEADER = "X-User-Id";

    private final Converter<String, Collection<GrantedAuthority>> permissionsConverter;

    public HeaderAuthenticationFilter(
            Converter<String, Collection<GrantedAuthority>> permissionsConverter) {
        this.permissionsConverter = permissionsConverter;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String role = request.getHeader(ROLE_HEADER);
        String permissionsJson = request.getHeader(PERMISSIONS_HEADER);
        String username = request.getHeader(USER_ID_HEADER);

        // Có role hoặc có permissions -> dựng Authentication từ Header
        if ((role != null && !role.isBlank()) || (permissionsJson != null && !permissionsJson.isBlank())) {

            List<GrantedAuthority> authorities = new ArrayList<>();

            // Bài 3 - RBAC: quyền theo role (không prefix ROLE_ vì spec dùng hasAuthority('STUDENT'))
            if (role != null && !role.isBlank()) {
                for (String r : role.split(",")) {
                    if (!r.isBlank()) {
                        authorities.add(new org.springframework.security.core.authority.SimpleGrantedAuthority(
                                r.trim()));
                    }
                }
            }

            // Bài 6 - PBAC: quyền chi tiết từ Header JSON, dùng Custom Converter
            if (permissionsJson != null && !permissionsJson.isBlank()) {
                authorities.addAll(permissionsConverter.convert(permissionsJson));
            }

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    username != null ? username : "anonymous", null, authorities);
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        filterChain.doFilter(request, response);
    }
}
