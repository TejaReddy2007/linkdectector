package com.linkguardian.repository;

import com.linkguardian.model.CommunityReport;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CommunityReportRepository extends JpaRepository<CommunityReport, Long> {
    List<CommunityReport> findAllByOrderByCreatedAtDesc();
}
