package com.myjwtapp.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/moderator")
public class ModeratorController {

    @PreAuthorize("hasRole('MODERATOR')")
    @GetMapping("/dashboard")
    public ResponseEntity<String> getModeratorDashboard() {
        return ResponseEntity.ok("Moderator Dashboard");
    }
}
