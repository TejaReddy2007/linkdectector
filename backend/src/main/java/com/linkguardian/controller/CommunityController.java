package com.linkguardian.controller;

import com.linkguardian.dto.ReportRequest;
import com.linkguardian.dto.ReportResponse;
import com.linkguardian.service.CommunityService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/community")
@CrossOrigin(origins = "*")
public class CommunityController {

    private final CommunityService communityService;

    public CommunityController(CommunityService communityService) {
        this.communityService = communityService;
    }

    @PostMapping("/report")
    public ResponseEntity<?> submitReport(@Valid @RequestBody ReportRequest request, 
                                          Authentication authentication) {
        try {
            String username = authentication.getName();
            ReportResponse response = communityService.submitReport(request, username);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new ErrorResponse(e.getMessage()));
        }
    }

    @GetMapping("/reports")
    public ResponseEntity<List<ReportResponse>> getAllReports() {
        try {
            List<ReportResponse> reports = communityService.getAllReports();
            return ResponseEntity.ok(reports);
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    private record ErrorResponse(String message) {}
}

