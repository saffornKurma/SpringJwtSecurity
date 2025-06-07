package com.security.securitytotal.jwtSecurity;

import org.springframework.security.authentication.AbstractAuthenticationToken;

public class JwtAuthToken extends AbstractAuthenticationToken {
    private final String token;

    public JwtAuthToken(String token) {
        super(null);
        this.token = token;
        setAuthenticated(false);
    }

    public String getToken() {
        return token;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }
}
