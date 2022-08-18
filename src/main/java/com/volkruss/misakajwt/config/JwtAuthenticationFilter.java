package com.volkruss.misakajwt.config;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager){
        this.authenticationManager = authenticationManager;
        setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login","POST"));
        setUsernameParameter("username");
        setPasswordParameter("password");
        this.setAuthenticationSuccessHandler((req,res,ex) -> {
            String token = JWT.create()
                    .withIssuer("com.volkruss.toaru")
                    .withClaim("username",ex.getName())
                    .sign(Algorithm.HMAC256("secret"));
            res.setHeader("X-AUTH-TOKEN",token);
            res.setStatus(200);
        });

        this.setAuthenticationFailureHandler((req,res,ex) -> {
            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        });

    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            ServletInputStream servletInputStream = request.getInputStream();
            LoginForm form = new ObjectMapper().readValue(request.getInputStream(),LoginForm.class);
            return this.authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(form.username,form.password,new ArrayList<>())
            );
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}