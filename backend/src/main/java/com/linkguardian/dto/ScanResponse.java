package com.linkguardian.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ScanResponse {
    private String url;
    private Boolean safe;
    private String virusTotalResult;
    private String googleSafeBrowsingResult;
    private String heuristicResult;
    private String message;
}
