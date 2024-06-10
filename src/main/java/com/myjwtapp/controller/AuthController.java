package com.myjwtapp.controller;

import com.myjwtapp.model.dto.request.LoginRequest;
import com.myjwtapp.model.dto.response.JwtResponse;
import com.myjwtapp.model.entity.User;
import com.myjwtapp.repository.UserRepository;
import com.myjwtapp.service.UserLoginAttemptService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static com.myjwtapp.service.JwtUtil.generationToken;


@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final UserLoginAttemptService userLoginAttemptService;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        User user = userRepository.findByUsername(loginRequest.getUsername()).orElseThrow(()->
                new UsernameNotFoundException("Didn't find user using login"));

        if (userLoginAttemptService.isAccountLocked(user)) {
            return ResponseEntity.status(423).body("Account locked due to too many failed attempts");
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
            );

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String token = generationToken(userDetails);
            userLoginAttemptService.resetFailedAttempts(user);

            return ResponseEntity.ok(new JwtResponse(token));
        } catch (AuthenticationException e) {
            userLoginAttemptService.increaseFailedAttempts(user);
            return ResponseEntity.status(401).body("Invalid password");
        }
    }
}
