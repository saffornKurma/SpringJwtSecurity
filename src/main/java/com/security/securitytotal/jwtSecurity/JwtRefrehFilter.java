package com.security.securitytotal.jwtSecurity;

import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtRefrehFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    public JwtRefrehFilter(AuthenticationManager authenticationManager, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if(!request.getServletPath().equals("/refresh-token")){
            filterChain.doFilter(request, response);
            return;
        }

        //refreshtoken
        String refreshToken = extractTokenFromRequestCookie(request);
        if(refreshToken == null){
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        JwtAuthToken jwtAuthToken = new JwtAuthToken(refreshToken);
        Authentication authentication = authenticationManager.authenticate(jwtAuthToken);

        if(authentication.isAuthenticated()){
            String newToken = jwtUtil.generateToken(authentication.getName(),15);
            response.addHeader("Authorization", "Bearer " + newToken);
        }
    }

    //refreshtoken
    private String extractTokenFromRequestCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        String refreshToken = null;
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if("refresh_token".equals(cookie.getName())){
                    refreshToken=cookie.getValue();
                }
            }
        }
        return refreshToken;
    }
}
