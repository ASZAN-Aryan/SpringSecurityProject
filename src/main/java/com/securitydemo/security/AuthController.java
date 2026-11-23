package com.securitydemo.security;

import jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtils jwtUtils;

    public record LoginRequest(String username, String password) {}
    public record JwtResponse(String token, String username) {}

    @PostMapping("/signin/user")
    public ResponseEntity<JwtResponse> signinUser(@RequestBody LoginRequest req) {
        return signin(req, "ROLE_USER");
    }

    @PostMapping("/signin/admin")
    public ResponseEntity<JwtResponse> signinAdmin(@RequestBody LoginRequest req) {
        return signin(req, "ROLE_ADMIN");
    }

    private ResponseEntity<JwtResponse> signin(LoginRequest req, String requiredRole) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.username(), req.password()));

        boolean hasRole = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals(requiredRole));
        if (!hasRole) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        String token = jwtUtils.generateToken(auth.getName());
        return ResponseEntity.ok(new JwtResponse(token, auth.getName()));
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Map<String, String>> handleBadCredentials(BadCredentialsException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Invalid username or password"));
    }
}