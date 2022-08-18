package com.volkruss.misakajwt.config;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

public class LoginFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String value = request.getHeader("X-AUTH-TOKEN");
        if(value == null || !value.startsWith("Bearer ")){
            SecurityContextHolder.getContext().setAuthentication(null);
            filterChain.doFilter(request,response);
            return;
        }
        String token = value.substring(7);
        DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC256("secret")).build().verify(token);
        String username = decodedJWT.getClaim("username").asString();
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(username,null,new ArrayList<>()));
        filterChain.doFilter(request,response);
    }
}