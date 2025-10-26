package com.linkguardian.service;

import com.linkguardian.dto.ReportRequest;
import com.linkguardian.dto.ReportResponse;
import com.linkguardian.model.CommunityReport;
import com.linkguardian.model.User;
import com.linkguardian.repository.CommunityReportRepository;
import com.linkguardian.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class CommunityService {

    private final CommunityReportRepository reportRepository;
    private final UserRepository userRepository;

    public CommunityService(CommunityReportRepository reportRepository, UserRepository userRepository) {
        this.reportRepository = reportRepository;
        this.userRepository = userRepository;
    }

    public ReportResponse submitReport(ReportRequest request, String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        CommunityReport report = new CommunityReport(
                user.getId(),
                request.getUrl(),
                request.getStatus(),
                request.getComment()
        );

        CommunityReport saved = reportRepository.save(report);

        return new ReportResponse(
                saved.getId(),
                saved.getUrl(),
                saved.getStatus(),
                saved.getComment(),
                username,
                saved.getCreatedAt()
        );
    }

    public List<ReportResponse> getAllReports() {
        List<CommunityReport> reports = reportRepository.findAllByOrderByCreatedAtDesc();

        return reports.stream()
                .map(report -> {
                    String username = userRepository.findById(report.getUserId())
                            .map(User::getUsername)
                            .orElse("Unknown");
                    
                    return new ReportResponse(
                            report.getId(),
                            report.getUrl(),
                            report.getStatus(),
                            report.getComment(),
                            username,
                            report.getCreatedAt()
                    );
                })
                .collect(Collectors.toList());
    }
}
