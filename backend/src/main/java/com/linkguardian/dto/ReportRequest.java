package com.linkguardian.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class ReportRequest {
    @NotBlank(message = "URL is required")
    private String url;

    @NotBlank(message = "Status is required")
    @Pattern(regexp = "^(safe|unsafe)$", message = "Status must be 'safe' or 'unsafe'")
    private String status;

    private String comment;
}

