/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package com.groupkma.EncryptAndMask.filter;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import com.groupkma.EncryptAndMask.util.JwtUtil;
import com.groupkma.EncryptAndMask.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;

/**
 *
 * @author minhp
 */

@Component
public class JwtAuthFilter extends OncePerRequestFilter{
    
    @Autowired
    private JwtUtil jwtUtil;
    
    @Autowired
    private UserService service;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) 
                throws ServletException, IOException {
        String path = request.getRequestURI();

        // Bỏ qua các endpoint public
        if (path.equals("/login") || path.equals("/register") || 
            path.equals("/api/user/login") || path.equals("/api/user/register")) {
            filterChain.doFilter(request, response);
            return;
        }
        String authHeader = request.getHeader("x-auth-token");
        String token = null;
        String id = null;
        if(authHeader == null || authHeader.isEmpty()){
            String cookies = request.getHeader("Cookie");
            if(cookies != null){
                String[] cookieArray = cookies.split(";");
                for(String cookie : cookieArray){
                    if(cookie.trim().startsWith("x-auth-token")){
                        token = cookie.trim().substring("x-auth-token=".length());
                        break;
                    }
                }
            }
            System.out.println("Token from cookie: " + token);
        } else {
            token = authHeader;
            System.out.println("Token from header: " + token);
        }
        
        if (token != null) {
            try {
                id = jwtUtil.extractId(token);
                System.out.println("Extracted ID: " + id);
            } catch (Exception e) {
                System.out.println("Error extracting ID from token: " + e.getMessage());
            }
        }
        
        // Xác thực người dùng
        if (id != null && SecurityContextHolder.getContext().getAuthentication() == null) { 
            UserDetails detail = service.loadUserByUsername(id); 
            if (jwtUtil.validateToken(token, detail)) { 
                System.out.println("Token validated successfully for user: " + id);
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(detail, null, detail.getAuthorities()); 
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)); 
                SecurityContextHolder.getContext().setAuthentication(authToken); 
            } else {
                System.out.println("Token validation failed for user: " + id);
            }
        } else {
            System.out.println("No valid ID or authentication already exists");
        }
        filterChain.doFilter(request, response); 
    }
}
