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
           .firstName(request.firstname())
           .lastName(request.lastname())
           .email(request.email())
           .password(passwordEncoder.encode(request.password()))
           .role(Role.USER)
           .build();
      repository.save(user);
      String jwtToken = jwtService.generateToken(user);
      return new AuthenticationResponse(jwtToken);
   }

   public AuthenticationResponse authenticate(AuthenticationRequest request) {
      authenticationManager.authenticate(
           new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
      );
      User user = repository
           .findByEmail(request.getEmail())
           .orElseThrow();

      String jwtToken = jwtService.generateToken(user);
      return new AuthenticationResponse(jwtToken);
   }
}
