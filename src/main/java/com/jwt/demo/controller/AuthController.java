package com.jwt.demo.controller;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;


import com.jwt.demo.dto.LoginDto;
import com.jwt.demo.dto.TokenDto;
import com.jwt.demo.entities.RefreshToken;
import com.jwt.demo.jwt.JwtFilter;
import com.jwt.demo.jwt.TokenProvider;
import com.jwt.demo.repository.RefreshTokenRepository;
import com.jwt.demo.service.AuthenticationService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class AuthController {
   
    private final AuthenticationService authenticationService;    
    
    @PostMapping("/login") // login
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginDto loginDto) {

    	Optional<TokenResponse> optTokenResponse = 
    			authenticationService.makeTokens(loginDto);
    	
    	HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + 
        		optTokenResponse.get().getAccessToken());
        
        ResponseEntity<TokenResponse> ret = new ResponseEntity<>(
        		optTokenResponse.get(), 
        		httpHeaders, 
        		HttpStatus.OK);
        
        return ret;
    } 
    
    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody 
    		RefreshTokenRequest refreshTokenRequest,
    		Authentication authentication) {    	
        
        try {
        	
        	Optional<TokenDto> tokenDto = 
        			authenticationService.makeNewAccessToken(
        					refreshTokenRequest, authentication);
        	
        	if (!tokenDto.isEmpty()) {
        		return ResponseEntity.ok(tokenDto.get());
        	} else {
        		return ResponseEntity.badRequest().body("Refresh token expired. Please login again.");
        	}            
            
        } catch (Exception e) {
            // 에러 처리 (예외 메시지 반환 등)
            return ResponseEntity.badRequest().body(e.getMessage());
        }        
    }
    
}