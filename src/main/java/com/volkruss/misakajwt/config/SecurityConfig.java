package com.volkruss.misakajwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
public class SecurityConfig {

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
        http.authorizeRequests(auth -> {
            auth.antMatchers("/get").permitAll();
            auth.antMatchers("/api/login").permitAll();
            auth.antMatchers("/post").authenticated();
        });
        http.cors().configurationSource(corsConfigurationSource());
        http.addFilter(new JwtAuthenticationFilter(authenticationManager(http.getSharedObject(AuthenticationConfiguration.class))));
        http.addFilterAfter(new LoginFilter(), JwtAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource(){
        CorsConfiguration cors = new CorsConfiguration();
        cors.setAllowedOrigins(Arrays.asList("http://localhost:3000"));
        cors.setAllowedMethods(Arrays.asList("GET","POST"));
        cors.setAllowedHeaders(Arrays.asList("*"));
        cors.setAllowCredentials(true);
        cors.addExposedHeader("X-AUTH-TOKEN");
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**",cors);
        return source;
    }

    @Bean
    public InMemoryUserDetailsManager userDetailsManager(){
        UserDetails user = User.withUsername("misaka")
                .password(
                        PasswordEncoderFactories
                                .createDelegatingPasswordEncoder()
                                .encode("mikoto"))
                                .roles("USER")
                                .build();
        return new InMemoryUserDetailsManager(user);
    }
}