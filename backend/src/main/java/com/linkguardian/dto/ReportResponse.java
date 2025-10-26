package com.linkguardian.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
public class ReportResponse {
    private Long id;
    private String url;
    private String status;
    private String comment;
    private String username;
    private LocalDateTime createdAt;
}

