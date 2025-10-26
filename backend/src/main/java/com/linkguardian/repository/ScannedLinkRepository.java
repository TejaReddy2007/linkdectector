package com.linkguardian.repository;

import com.linkguardian.model.ScannedLink;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ScannedLinkRepository extends JpaRepository<ScannedLink, Long> {
    List<ScannedLink> findByUserIdOrderByScannedAtDesc(Long userId);
    List<ScannedLink> findByUserIdAndSafeOrderByScannedAtDesc(Long userId, Boolean safe);
}


