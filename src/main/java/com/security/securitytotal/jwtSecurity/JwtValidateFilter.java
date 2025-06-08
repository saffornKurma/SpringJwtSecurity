package com.security.securitytotal.jwtSecurity;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtValidateFilter extends OncePerRequestFilter {


    private final AuthenticationManager authenticationManager;

    public JwtValidateFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String token=extractJwt(request);
        if(token!=null){
            JwtAuthToken tokenObj=new JwtAuthToken(token);
            Authentication result=authenticationManager.authenticate(tokenObj);
            SecurityContextHolder.getContext().setAuthentication(result);
        }

filterChain.doFilter(request, response);
    }
    public String extractJwt(HttpServletRequest request) {
        String token = request.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
            System.out.println("token receiv ed during token extraction validation:"+token);
            return token;
        }
        return null;
    }


}
