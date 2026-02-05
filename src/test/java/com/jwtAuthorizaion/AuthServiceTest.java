package com.jwtAuthorizaion;

import com.jwtAuthorizaion.dto.SignupRequest;
import com.jwtAuthorizaion.entity.User;
import com.jwtAuthorizaion.repository.UserRepository;
import com.jwtAuthorizaion.service.AuthService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private AuthService authService;

    @Test
    void register_shouldSaveUser_whenUserDoesNotExist() {
        // Arrange
        SignupRequest request = new SignupRequest();
        request.setEmail("test@example.com");
        request.setPassword("password123");
        request.setRole("ADMIN");

        when(userRepository.findByEmail(request.getEmail()))
                .thenReturn(Optional.empty());
        when(passwordEncoder.encode(request.getPassword()))
                .thenReturn("encodedPassword");

        // Act
        authService.register(request);

        // Assert
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());

        User savedUser = userCaptor.getValue();
        assertEquals("test@example.com", savedUser.getEmail());
        assertEquals("encodedPassword", savedUser.getPassword());
        assertEquals("ADMIN", savedUser.getRole());
    }

    @Test
    void register_shouldThrowException_whenUserAlreadyExists() {
        // Arrange
        SignupRequest request = new SignupRequest();
        request.setEmail("test@example.com");

        when(userRepository.findByEmail(request.getEmail()))
                .thenReturn(Optional.of(new User()));

        // Act & Assert
        RuntimeException exception = assertThrows(
                RuntimeException.class,
                () -> authService.register(request)
        );

        assertEquals("User already exists", exception.getMessage());
        verify(userRepository, never()).save(any());
    }

    @Test
    void register_shouldAssignDefaultRole_whenRoleIsNull() {
        // Arrange
        SignupRequest request = new SignupRequest();
        request.setEmail("user@example.com");
        request.setPassword("password123");
        request.setRole(null);

        when(userRepository.findByEmail(request.getEmail()))
                .thenReturn(Optional.empty());
        when(passwordEncoder.encode(request.getPassword()))
                .thenReturn("encodedPassword");

        // Act
        authService.register(request);

        // Assert
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());

        User savedUser = userCaptor.getValue();
        assertEquals("USER", savedUser.getRole());
    }
}