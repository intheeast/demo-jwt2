package com.jwt.demo.jwt;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    	http.cors(cors -> cors.disable());
    	http.csrf(csrf -> csrf.disable());
    	
    	http.headers(headers -> headers.frameOptions().disable());
    	
    	http.exceptionHandling(
    			e -> e.authenticationEntryPoint(jwtAuthenticationEntryPoint)
    			.accessDeniedHandler(jwtAccessDeniedHandler));
    	
    	http.sessionManagement(
    			sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
    	
    	http.authorizeHttpRequests(
    			c -> c.requestMatchers(new AntPathRequestMatcher("/api/login")).permitAll() // 로그인 api
    			.requestMatchers(new AntPathRequestMatcher("/api/refresh-token")).permitAll()	
    			.requestMatchers(new AntPathRequestMatcher("/api/signup")).permitAll() // 회원가입 api
    				.requestMatchers(new AntPathRequestMatcher("/favicon.ico")).permitAll()
    				.anyRequest().authenticated()
    			);
    	   	
    	http.apply(new JwtSecurityConfig(tokenProvider));
    	
    	
        return http.build();
    }
    
}