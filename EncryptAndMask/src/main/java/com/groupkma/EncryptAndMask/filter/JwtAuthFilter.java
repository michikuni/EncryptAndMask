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
        String authHeader = request.getHeader("x-auth-token");
        String token = null;
        String id = null;
        String pass = null;
        if(authHeader != null){
            token = authHeader;
            id = jwtUtil.extractId(token);
        }
        
        if (id != null && SecurityContextHolder.getContext().getAuthentication() == null) { 
            UserDetails detail = service.loadUserByUsername(id); 
            if (jwtUtil.validateToken(token, detail)) { 
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(detail, null, null); 
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)); 
                SecurityContextHolder.getContext().setAuthentication(authToken); 
            } 
        } 
        filterChain.doFilter(request, response); 
    }
}
