package com.micro.auth.controllers;

import com.micro.auth.entities.User;
import com.micro.auth.pojo.AuthRequest;
import com.micro.auth.jwtUtils.JwtTokenUtil;
import com.micro.auth.pojo.AuthResponse;
import com.micro.auth.services.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenUtil jwtTokenUtil;
    private final UserService userService;

    public AuthController(AuthenticationManager authenticationManager, JwtTokenUtil jwtTokenUtil, UserService userService) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenUtil = jwtTokenUtil;
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody AuthRequest authRequest) {
        if (userService.existsUser(authRequest.getUsername())) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Пользователь уже существует");
        }

        User newUser = userService.saveUser(authRequest.getUsername(), authRequest.getPassword());
        return ResponseEntity.status(HttpStatus.CREATED).body(newUser);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest authRequest) {
        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())
            );

            String role = String.valueOf(userService.findByUsername(authRequest.getUsername()).getRole());
            String token = jwtTokenUtil.generateToken(authRequest.getUsername(), auth);

            return ResponseEntity.ok(new AuthResponse(token, authRequest.getUsername(), role));
        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Неверные логин и/или пароль");
        }
    }


    @PostMapping("/validate_token")
    public ResponseEntity<?> validate(@RequestHeader("Authorization") String token) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            return ResponseEntity.ok("Токен действителен, пользователь: " + authentication.getName());
        } else {
            return ResponseEntity.status(401).body("Токен недействителен");
        }
    }
}
