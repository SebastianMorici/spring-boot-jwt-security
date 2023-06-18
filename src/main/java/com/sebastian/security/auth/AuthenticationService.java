package com.sebastian.security.auth;

import com.sebastian.security.config.JwtService;
import com.sebastian.security.user.Role;
import com.sebastian.security.user.User;
import com.sebastian.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

   private final UserRepository repository;
   private final PasswordEncoder passwordEncoder;
   private final JwtService jwtService;
   private final AuthenticationManager authenticationManager;

   public AuthenticationResponse register(RegisterRequest request) {
      User user = User.builder()
           .firstName(request.getFirstname())
           .lastName(request.getLastname())
           .email(request.getEmail())
           .password(passwordEncoder.encode(request.getPassword()))
           .role(Role.USER)
           .build();
      repository.save(user);
      String jwtToken = jwtService.generateToken(user);
      return AuthenticationResponse.builder()
           .token(jwtToken)
           .build();
   }

   public AuthenticationResponse authenticate(AuthenticationRequest request) {
      authenticationManager.authenticate(
           new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
      );
      User user = repository
           .findByEmail(request.getEmail())
           .orElseThrow();

      String jwtToken = jwtService.generateToken(user);
      return AuthenticationResponse.builder()
           .token(jwtToken)
           .build();
   }
}
