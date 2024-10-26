package com.micro.auth.controllers;

import com.micro.auth.entities.User;
import com.micro.auth.pojo.AuthRequest;
import com.micro.auth.pojo.AuthResponse;
import com.micro.auth.services.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserService userService;

    public AuthController(AuthenticationManager authenticationManager, UserService userService) {
        this.authenticationManager = authenticationManager;
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
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())
            );

            String role = String.valueOf(userService.findByUsername(authRequest.getUsername()).getRole());
            String token = userService.generateToken(authRequest.getUsername(), role);

            return new ResponseEntity<>(new AuthResponse(authRequest.getUsername(), role, token), HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>("Неверные логин и/или пароль", HttpStatus.UNAUTHORIZED);
        }
    }


    @PostMapping("/validate")
    public AuthResponse validate(@RequestHeader("Authorization") String token) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()
                && !"anonymousUser".equals(authentication.getName())) {
            return new AuthResponse(userService.getUsernameFromToken(token),
                    userService.getRoleFromToken(token), "");
        } else {
            return new AuthResponse();
        }
    }
}
