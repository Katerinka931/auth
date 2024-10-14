package com.micro.auth.pojo;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthResponse {
    private String token;
    private String username;
    private String message;

    public AuthResponse(String token) {
        this.token = token;
    }
}
