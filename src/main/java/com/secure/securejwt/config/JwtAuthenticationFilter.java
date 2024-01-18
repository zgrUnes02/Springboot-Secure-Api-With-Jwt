package com.secure.securejwt.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private JwtService jwtService ;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization") ; // Bearer token
        final String token ;
        final String userEmail ;
        if ( authHeader == null || !authHeader.startsWith("Bearer ") ) {
            filterChain.doFilter(request , response);
            return ;
        } else {
            token = authHeader.substring(7) ;
            userEmail = jwtService.extractUserEmail(token) ;
        }
    }
}
