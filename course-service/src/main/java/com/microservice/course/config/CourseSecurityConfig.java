package com.microservice.course.config;

import com.microservice.course.security.HeaderAuthenticationFilter;
import com.microservice.course.security.PermissionsHeaderConverter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;

/**
 * Bài 3 - A/C. Cấu hình Security cho Course-Service (Resource Server).
 *
 * Course-Service KHÔNG validate lại JWT - nó tin Gateway.
 * Quyền được đọc trực tiếp từ Header X-User-Role / X-User-Permissions.
 */
@Configuration
@EnableWebSecurity
// Bài 3 - A: kích hoạt @PreAuthorize
@EnableMethodSecurity
public class CourseSecurityConfig {

    /**
     * Bài 6 - B. Custom Converter: JSON string (Header X-User-Permissions) -> GrantedAuthority.
     */
    @Bean
    public Converter<String, Collection<GrantedAuthority>> permissionsHeaderConverter() {
        return new PermissionsHeaderConverter();
    }

    @Bean
    public HeaderAuthenticationFilter headerAuthenticationFilter(
            Converter<String, Collection<GrantedAuthority>> permissionsHeaderConverter) {
        return new HeaderAuthenticationFilter(permissionsHeaderConverter);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   HeaderAuthenticationFilter headerAuthenticationFilter)
            throws Exception {
        http
                // Stateless -> tắt CSRF
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/**").permitAll()
                        // Giữ nguyên status code gốc khi Boot chuyển hướng lỗi
                        .requestMatchers("/error").permitAll()
                        .anyRequest().authenticated())
                .addFilterBefore(headerAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(ex -> ex.authenticationEntryPoint(
                        (HttpServletRequest request, HttpServletResponse response,
                         org.springframework.security.core.AuthenticationException e) -> {
                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                            response.setContentType("application/json;charset=UTF-8");
                            response.getWriter().write(
                                    "{\"error\": \"Unauthorized\", \"message\": \"Missing X-User-Role header\"}");
                        }));

        return http.build();
    }
}
