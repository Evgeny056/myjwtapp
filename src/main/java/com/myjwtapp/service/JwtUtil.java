package com.myjwtapp.service;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.security.Key;
import java.util.ArrayList;
import java.util.Date;

public class JwtUtil {

    private static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS512);
    private static final long EXPIRATION_TIME = 86400;

    public static String generationToken(UserDetails userDetails) {

        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SECRET_KEY)
                .compact();
    }

    public static boolean validateToken(String token, UserDetails userDetails) {
        String username = extractUsernameFromToken(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    public static boolean validateToken(String token) {
        try{
            Jwts
                    .parserBuilder()
                    .setSigningKey(SECRET_KEY)
                    .build()
                    .parseClaimsJwt(token);

            return true;

        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    private static String extractUsernameFromToken(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJwt(token)
                .getBody()
                .getSubject();
    }

    private static boolean isTokenExpired(String token) {
        Date expirationDate = Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJwt(token)
                .getBody()
                .getExpiration();

        return expirationDate.before(new Date());
    }

    public static UserDetails extractUserDetailsFromToken(String token) {
        String username = Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();      //получаем имя пользователя из токена

        //TODO дописать логику получения UserDetails по имени пользователя (например из БД)
        return new User(username, "", new ArrayList<>());
    }
}
