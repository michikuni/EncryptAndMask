/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package com.groupkma.EncryptAndMask.util;

import org.springframework.stereotype.Component;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import io.jsonwebtoken.Jwts;
import org.springframework.security.core.userdetails.UserDetails;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

/**
 *
 * @author minhp
 */

@Component
public class JwtUtil {
    public static final String SECRET = "7pX9kR4mW2vJ8tL5qY3nZ6bF0sH7dA1cE4iG9oP2=";
    public String generateToken(String id, String password){
        Map<String, Object> claims = new HashMap<>();
        claims.put("pass", password);
        return createToken(claims, id);
    }
    
    private String createToken(Map<String, Object> claims, String id){
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(id) 
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000 * 60 * 30))
                .signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
    }
    private Key getSignKey() { 
        byte[] keyBytes= Decoders.BASE64.decode(SECRET); 
        return Keys.hmacShaKeyFor(keyBytes); 
    }
  
    public String extractId(String token) { 
        return extractClaim(token, Claims::getSubject); 
    } 
  
    public Date extractExpiration(String token) { 
        return extractClaim(token, Claims::getExpiration); 
    } 
    
    public String extractPass(String token) {
    	return extractClaim(token, claims -> (String) claims.get("pass"));
    }
  
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) { 
        final Claims claims = extractAllClaims(token); 
        return claimsResolver.apply(claims); 
    } 
  
    private Claims extractAllClaims(String token) { 
        return Jwts 
                .parserBuilder() 
                .setSigningKey(getSignKey()) 
                .build() 
                .parseClaimsJws(token) 
                .getBody(); 
    } 
  
    private Boolean isTokenExpired(String token) { 
        return extractExpiration(token).before(new Date()); 
    } 
  
    public Boolean validateToken(String token, UserDetails details) { 
        final String username = extractId(token); 
        return (username.equals(details.getUsername()) && !isTokenExpired(token)); 
    } 
}
