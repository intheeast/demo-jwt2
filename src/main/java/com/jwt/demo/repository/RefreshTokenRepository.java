package com.jwt.demo.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.jwt.demo.entities.RefreshToken;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String> {
}
