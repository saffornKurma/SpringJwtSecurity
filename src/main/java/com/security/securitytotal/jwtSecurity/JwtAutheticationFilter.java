package com.security.securitytotal.jwtSecurity;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtAutheticationFilter extends OncePerRequestFilter {


    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    public JwtAutheticationFilter(AuthenticationManager authenticationManager, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {


        if(!request.getServletPath().equals("/generate-token")) {
            filterChain.doFilter(request, response);
            return;
        }


        ObjectMapper objectMapper = new ObjectMapper();
        LoginRequest loginRequest = objectMapper.readValue(request.getInputStream(), LoginRequest.class);

        UsernamePasswordAuthenticationToken authToken=new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword());

        Authentication authObj= authenticationManager.authenticate(authToken);

        if(authObj.isAuthenticated())
        {
            String token=jwtUtil.generateToken(authObj.getName());
            response.addHeader("Authorization","Bearer "+token);
        }

    }
}
