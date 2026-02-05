package com.jwtAuthorizaion;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import com.jwtAuthorizaion.service.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collections;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {

    private JwtService jwtService;
    private UserDetails userDetails;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();
        userDetails = new User(
                "test@example.com",
                "password",
                Collections.emptyList()
        );
    }

    @Test
    void generateToken_shouldReturnValidJwt() {
        // Act
        String token = jwtService.generateToken(userDetails);

        // Assert
        assertNotNull(token);
        assertFalse(token.isEmpty());
    }

    @Test
    void extractUsername_shouldReturnCorrectUsername() {
        // Arrange
        String token = jwtService.generateToken(userDetails);

        // Act
        String username = jwtService.extractUsername(token);

        // Assert
        assertEquals("test@example.com", username);
    }

    @Test
    void isTokenValid_shouldReturnTrue_whenTokenIsValid() {
        // Arrange
        String token = jwtService.generateToken(userDetails);

        // Act
        boolean isValid = jwtService.isTokenValid(token, userDetails);

        // Assert
        assertTrue(isValid);
    }

    @Test
    void isTokenValid_shouldReturnFalse_whenUsernameDoesNotMatch() {
        // Arrange
        String token = jwtService.generateToken(userDetails);

        UserDetails anotherUser = new User(
                "other@example.com",
                "password",
                Collections.emptyList()
        );

        // Act
        boolean isValid = jwtService.isTokenValid(token, anotherUser);

        // Assert
        assertFalse(isValid);
    }

    @Test
    void isTokenValid_shouldReturnFalse_whenTokenIsExpired() {
        // Arrange
        JwtService expiredJwtService = new JwtService() {
            @Override
            public String generateToken(UserDetails userDetails) {
                return io.jsonwebtoken.Jwts.builder()
                        .setSubject(userDetails.getUsername())
                        .setIssuedAt(new Date(System.currentTimeMillis() - 2 * 60 * 60 * 1000))
                        .setExpiration(new Date(System.currentTimeMillis() - 60 * 60 * 1000))
                        .signWith(io.jsonwebtoken.security.Keys.hmacShaKeyFor(
                                "mysecretkeymysecretkeymysecretkey".getBytes()
                        ))
                        .compact();
            }
        };

        String expiredToken = expiredJwtService.generateToken(userDetails);

        // Act
        boolean isValid = jwtService.isTokenValid(expiredToken, userDetails);

        // Assert
        assertFalse(isValid);
    }
}
