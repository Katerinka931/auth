package com.micro.auth.services;

import com.micro.auth.entities.User;
import com.micro.auth.enums.UserRole;
import com.micro.auth.jwtUtils.JwtTokenUtil;
import com.micro.auth.repositories.UserRepository;
import io.jsonwebtoken.Claims;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {
    private final JwtTokenUtil jwtTokenUtil;
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public UserService(JwtTokenUtil jwtTokenUtil, UserRepository userRepository, BCryptPasswordEncoder passwordEncoder) {
        this.jwtTokenUtil = jwtTokenUtil;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public User saveUser(String username, String password) {
        User user = new User();
        user.setUsername(username);
        user.setRole(UserRole.ROLE_USER);
        user.setPassword(passwordEncoder.encode(password));
        return userRepository.save(user);
    }

    public User findByUsername(String username) {
        Optional<User> user = userRepository.findByUsername(username);
        return user.orElseThrow();
    }

    public boolean existsUser(String username) {
        return userRepository.findByUsername(username).isPresent();
    }

    public String getUsernameFromToken(String token) {
        return jwtTokenUtil.getUsernameFromToken(token);
    }

    public String getRoleFromToken(String token) {
        Claims claims = jwtTokenUtil.getClaimsFromToken(token);
        return claims.get("role", String.class);
    }

    public String generateToken(String username, String role) {
        return jwtTokenUtil.generateToken(username, role);
    }
}
