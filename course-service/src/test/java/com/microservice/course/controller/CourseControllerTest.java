package com.microservice.course.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Bài 3 & Bài 6 - Kiểm thử phân quyền tại Resource Server.
 */
@SpringBootTest
@AutoConfigureMockMvc
class CourseControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void studentWithCourseReadCanListCourses() throws Exception {
        mockMvc.perform(get("/api/courses")
                        .with(authentication(org.springframework.security.authentication.UsernamePasswordAuthenticationToken
                                .authenticated("student01", null,
                                        java.util.List.of(
                                                new org.springframework.security.core.authority.SimpleGrantedAuthority("STUDENT"),
                                                new org.springframework.security.core.authority.SimpleGrantedAuthority("COURSE_READ"))))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }

    @Test
    void studentCannotCreateCourse() throws Exception {
        mockMvc.perform(post("/api/courses")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Should Be Forbidden\"}")
                        .with(authentication(org.springframework.security.authentication.UsernamePasswordAuthenticationToken
                                .authenticated("student01", null,
                                        java.util.List.of(
                                                new org.springframework.security.core.authority.SimpleGrantedAuthority("STUDENT"),
                                                new org.springframework.security.core.authority.SimpleGrantedAuthority("COURSE_READ"))))))
                .andExpect(status().isForbidden());
    }

    @Test
    void instructorCanCreateCourse() throws Exception {
        mockMvc.perform(post("/api/courses")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Test Course\"}")
                        .with(authentication(org.springframework.security.authentication.UsernamePasswordAuthenticationToken
                                .authenticated("instructor01", null,
                                        java.util.List.of(
                                                new org.springframework.security.core.authority.SimpleGrantedAuthority("INSTRUCTOR"),
                                                new org.springframework.security.core.authority.SimpleGrantedAuthority("COURSE_WRITE"))))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value("Test Course"));
    }
}
