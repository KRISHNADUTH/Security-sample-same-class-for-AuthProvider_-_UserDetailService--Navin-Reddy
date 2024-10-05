package com.example.demo.filter;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.demo.config.MyUserDetailService;
import com.example.demo.service.JwtService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NoArgsConstructor;

@Component
@NoArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private ApplicationContext context;
    
    @Autowired
    private JwtService jwtTokenService;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        System.out.println("JwtTokenValidationFilter IS CAAAAAAALEEDDDDDDDDDDDDDDDD");
        String authorizationHeader = request.getHeader("Authorization");
        System.out.println("Authorization from request isssssssssssssssss = "+authorizationHeader);
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            System.out.println("Inside IF Authorization from request isssssssssssssssss = "+authorizationHeader);
            String jwtToken = authorizationHeader.substring(7);
            String username = jwtTokenService.extractUsername(jwtToken);
            System.out.println("Extracted user name issssssss = "+username);
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = context.getBean(MyUserDetailService.class).loadUserByUsername(username);
                if (jwtTokenService.validateToken(jwtToken, userDetails)) {
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                                                                                userDetails.getUsername(), null, userDetails.getAuthorities());
                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                } else {
                    throw new BadCredentialsException("JWT token validation failed........");
                }
            }

        }
        filterChain.doFilter(request, response);
    }

}
