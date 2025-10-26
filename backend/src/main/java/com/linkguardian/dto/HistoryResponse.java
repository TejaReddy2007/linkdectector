package com.linkguardian.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
public class HistoryResponse {
    private Long id;
    private String url;
    private Boolean safe;
    private LocalDateTime scannedAt;
}
 

