package com.linkguardian.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class ScanRequest {
    @NotBlank(message = "URL is required")
    private String url;
}

