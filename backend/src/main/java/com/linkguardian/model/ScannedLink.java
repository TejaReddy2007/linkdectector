package com.linkguardian.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "scanned_links")
@Data
@NoArgsConstructor
public class ScannedLink {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(nullable = false, length = 2048)
    private String url;

    @Column(nullable = false)
    private Boolean safe;

    @Column(name = "virus_total_result", columnDefinition = "TEXT")
    private String virusTotalResult;

    @Column(name = "google_safe_browsing_result", columnDefinition = "TEXT")
    private String googleSafeBrowsingResult;

    @Column(name = "heuristic_result", columnDefinition = "TEXT")
    private String heuristicResult;

    @CreationTimestamp
    @Column(name = "scanned_at", nullable = false, updatable = false)
    private LocalDateTime scannedAt;

    public ScannedLink(Long userId, String url, Boolean safe) {
        this.userId = userId;
        this.url = url;
        this.safe = safe;
    }
}

