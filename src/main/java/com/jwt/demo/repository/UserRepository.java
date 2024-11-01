package com.jwt.demo.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
//import org.springframework.data.repository.Repository;
//import org.springframework.stereotype.Repository;


import com.jwt.demo.entities.User;

//@Repository
public interface UserRepository extends JpaRepository <User, Long> {

	Optional<User> findById(Long id);
	User save(User user);	
	Optional<User> findOneWithAuthoritiesByUsername(String username);
	void delete(User user);
}
