package com.linkguardian.controller;

import com.linkguardian.dto.HistoryResponse;
import com.linkguardian.service.HistoryService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/history")
@CrossOrigin(origins = "*")
public class HistoryController {

    private final HistoryService historyService;

    public HistoryController(HistoryService historyService) {
        this.historyService = historyService;
    }

    @GetMapping
    public ResponseEntity<List<HistoryResponse>> getHistory(
            @RequestParam(defaultValue = "all") String filter,
            Authentication authentication) {
        try {
            String username = authentication.getName();
            List<HistoryResponse> history = historyService.getUserHistory(username, filter);
            return ResponseEntity.ok(history);
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }
}
