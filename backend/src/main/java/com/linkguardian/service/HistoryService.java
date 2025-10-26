package com.linkguardian.service;

import com.linkguardian.dto.HistoryResponse;
import com.linkguardian.model.ScannedLink;
import com.linkguardian.model.User;
import com.linkguardian.repository.ScannedLinkRepository;
import com.linkguardian.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class HistoryService {

    private final ScannedLinkRepository scannedLinkRepository;
    private final UserRepository userRepository;

    public HistoryService(ScannedLinkRepository scannedLinkRepository, UserRepository userRepository) {
        this.scannedLinkRepository = scannedLinkRepository;
        this.userRepository = userRepository;
    }

    public List<HistoryResponse> getUserHistory(String username, String filter) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        List<ScannedLink> links;
        
        if ("safe".equalsIgnoreCase(filter)) {
            links = scannedLinkRepository.findByUserIdAndSafeOrderByScannedAtDesc(user.getId(), true);
        } else if ("unsafe".equalsIgnoreCase(filter)) {
            links = scannedLinkRepository.findByUserIdAndSafeOrderByScannedAtDesc(user.getId(), false);
        } else {
            links = scannedLinkRepository.findByUserIdOrderByScannedAtDesc(user.getId());
        }

        return links.stream()
                .map(link -> new HistoryResponse(
                        link.getId(),
                        link.getUrl(),
                        link.getSafe(),
                        link.getScannedAt()
                ))
                .collect(Collectors.toList());
    }
}
