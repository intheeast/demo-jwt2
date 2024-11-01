package com.jwt.demo.service;

import java.time.LocalDateTime;
import java.util.Optional;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import io.jsonwebtoken.io.Decoders;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;

import com.jwt.demo.controller.RefreshTokenRequest;
import com.jwt.demo.controller.TokenResponse;
import com.jwt.demo.dto.LoginDto;
import com.jwt.demo.dto.TokenDto;
import com.jwt.demo.entities.RefreshToken;
import com.jwt.demo.jwt.JwtFilter;
import com.jwt.demo.jwt.TokenProvider;
import com.jwt.demo.repository.RefreshTokenRepository;

@Slf4j
@RequiredArgsConstructor
@Service
public class AuthenticationService {
	
	private final TokenProvider tokenProvider;
    @Autowired
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;	
	
	public Optional<TokenResponse> makeTokens(LoginDto loginDto) {
		log.info("makeTokens");
    	
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        log.info("username=" + authentication.getName());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String accessToken = tokenProvider.createToken(authentication, true);
        String refreshToken = tokenProvider.createAndPersistRefreshTokenForUser(authentication);
        
        TokenResponse tokenResponse = new TokenResponse(accessToken,
        		refreshToken);
        
        Optional<TokenResponse> optTokenResponse = 
        		Optional.ofNullable(tokenResponse);        
        
        return optTokenResponse;        
	}
	
	@Transactional
	public Optional<TokenDto> makeNewAccessToken(RefreshTokenRequest refreshTokenRequest,
    		Authentication authentication) {
		String refreshTokenValue = refreshTokenRequest.getRefreshToken();		
    	
    	log.info("refreshToken from user. token value=" + refreshTokenValue);
    	
        RefreshToken validRefreshToken = 
        		refreshTokenRepository.findById(refreshTokenValue)
                .orElseThrow(() -> new IllegalStateException("Invalid refresh token"));

        TokenDto tokenDto = null;
        Optional<TokenDto> optTokenDto = null;
        if (isTokenExpired(validRefreshToken)) {
            refreshTokenRepository.delete(validRefreshToken);
            optTokenDto = Optional.ofNullable(tokenDto);
            return optTokenDto;
        }
        
        log.info("refreshToken from database. token value=" + validRefreshToken.getToken());
        
        String accessToken = tokenProvider.createToken(authentication, true);
        
        tokenDto = new TokenDto(accessToken);
        optTokenDto = Optional.ofNullable(tokenDto);
        return optTokenDto;
        
	}
	
	public boolean isTokenExpired(RefreshToken refreshToken) {
        return refreshToken.getExpiryDate().isBefore(LocalDateTime.now());
    }
	
}
