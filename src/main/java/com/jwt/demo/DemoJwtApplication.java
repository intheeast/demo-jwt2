package com.jwt.demo;

import java.util.Collections;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.jwt.demo.dto.UserDto;
import com.jwt.demo.entities.Authority;
import com.jwt.demo.entities.User;
import com.jwt.demo.repository.UserRepository;

@SpringBootApplication
public class DemoJwtApplication {
	
	@Bean
	public CommandLineRunner dataLoader(
			UserRepository userRepository,
			PasswordEncoder passwordEncoder
			) {
		
		return new CommandLineRunner() {
		      @Override
		      public void run(String... args) throws Exception {
		    	  Authority authority = Authority.builder()
		                  .authorityName("ROLE_USER")
		                  .build();
		    	  
		    	  UserDto userDto = UserDto.builder()
		    			  .username("intheeast0305@gmail.com")
		    			  .password("12345")
		    			  .nickname("sungwon")
		    			  .build();
		    	  
		    	  User user = User.builder()
		                  .username(userDto.getUsername())
		                  .password(passwordEncoder.encode(userDto.getPassword()))
		                  .nickname(userDto.getNickname())
		                  .authorities(Collections.singleton(authority))
		                  .activated(true)
		                  .build();

		          userRepository.save(user);
		      }
		};
		
	}

	public static void main(String[] args) {
		SpringApplication.run(DemoJwtApplication.class, args);
	}

}
