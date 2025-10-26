package com.linkguardian.controller;

import com.linkguardian.dto.ScanRequest;
import com.linkguardian.dto.ScanResponse;
import com.linkguardian.service.ScanService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class ScanController {

    private final ScanService scanService;

    public ScanController(ScanService scanService) {
        this.scanService = scanService;
    }

    @PostMapping("/scan")
    public ResponseEntity<?> scanUrl(@Valid @RequestBody ScanRequest request, Authentication authentication) {
        try {
            String username = authentication.getName();
            ScanResponse response = scanService.scanUrl(request, username);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new ErrorResponse(e.getMessage()));
        }
    }

    private record ErrorResponse(String message) {}
}

