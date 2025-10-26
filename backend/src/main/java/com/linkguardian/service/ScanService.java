package com.linkguardian.service;

import com.linkguardian.dto.ScanRequest;
import com.linkguardian.dto.ScanResponse;
import com.linkguardian.model.ScannedLink;
import com.linkguardian.model.User;
import com.linkguardian.repository.ScannedLinkRepository;
import com.linkguardian.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.regex.Pattern;

@Service
public class ScanService {

    @Value("${virustotal.api.key}")
    private String virusTotalApiKey;

    @Value("${google.safebrowsing.api.key}")
    private String googleApiKey;

    private final ScannedLinkRepository scannedLinkRepository;
    private final UserRepository userRepository;
    private final HttpClient httpClient;

    public ScanService(ScannedLinkRepository scannedLinkRepository, UserRepository userRepository) {
        this.scannedLinkRepository = scannedLinkRepository;
        this.userRepository = userRepository;
        this.httpClient = HttpClient.newHttpClient();
    }

    public ScanResponse scanUrl(ScanRequest request, String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        String url = request.getUrl();

        // Run all three scans
        String vtResult = checkVirusTotal(url);
        String gsbResult = checkGoogleSafeBrowsing(url);
        String heuristicResult = checkHeuristics(url);

        // Determine overall safety
        boolean safe = determineOverallSafety(vtResult, gsbResult, heuristicResult);

        // Save to database
        ScannedLink scannedLink = new ScannedLink(user.getId(), url, safe);
        scannedLink.setVirusTotalResult(vtResult);
        scannedLink.setGoogleSafeBrowsingResult(gsbResult);
        scannedLink.setHeuristicResult(heuristicResult);
        scannedLinkRepository.save(scannedLink);

        String message = safe ? "No threats detected" : "Potential threats detected";
        
        return new ScanResponse(url, safe, vtResult, gsbResult, heuristicResult, message);
    }

    private String checkVirusTotal(String url) {
        try {
            // VirusTotal v3 API
            String apiUrl = "https://www.virustotal.com/api/v3/urls";
            
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(apiUrl))
                    .header("x-apikey", virusTotalApiKey)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString("url=" + url))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                // Parse JSON response (simplified)
                String body = response.body();
                if (body.contains("\"malicious\":0")) {
                    return "✅ Clean - No malicious detections";
                } else {
                    return "⚠️ Threats detected by VirusTotal";
                }
            } else {
                return "❓ VirusTotal check unavailable (check API key)";
            }
        } catch (Exception e) {
            return "❌ VirusTotal error: " + e.getMessage();
        }
    }

    private String checkGoogleSafeBrowsing(String url) {
        try {
            String apiUrl = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + googleApiKey;
            
            String requestBody = String.format("""
                {
                    "client": {
                        "clientId": "linkguardian",
                        "clientVersion": "1.0.0"
                    },
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": "%s"}]
                    }
                }
                """, url);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(apiUrl))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                String body = response.body();
                if (body.contains("matches")) {
                    return "⚠️ Flagged by Google Safe Browsing";
                } else {
                    return "✅ Clean - No threats found";
                }
            } else {
                return "❓ Google Safe Browsing check unavailable (check API key)";
            }
        } catch (Exception e) {
            return "❌ Google Safe Browsing error: " + e.getMessage();
        }
    }

    private String checkHeuristics(String url) {
        int score = 0;
        StringBuilder analysis = new StringBuilder();

        // Convert to lowercase for analysis
        String lowerUrl = url.toLowerCase();

        // 1. HTTPS check
        if (lowerUrl.startsWith("https://")) {
            score += 2;
            analysis.append("✅ Uses HTTPS (+2). ");
        } else if (lowerUrl.startsWith("http://")) {
            score -= 2;
            analysis.append("⚠️ No HTTPS (-2). ");
        }

        // 2. IP address check
        if (Pattern.matches(".*\\d+\\.\\d+\\.\\d+\\.\\d+.*", lowerUrl)) {
            score -= 5;
            analysis.append("⚠️ Uses IP address (-5). ");
        }

        // 3. URL shortener check
        String[] shorteners = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"};
        for (String shortener : shorteners) {
            if (lowerUrl.contains(shortener)) {
                score -= 3;
                analysis.append("⚠️ URL shortener detected (-3). ");
                break;
            }
        }

        // 4. Suspicious keywords (phishing/scam related)
        String[] suspiciousKeywords = {
            "verify", "account", "suspend", "confirm", "update", "secure", "bank", "paypal",
            "ebay", "amazon", "login", "signin", "password", "urgent", "click", "winner",
            "free", "prize", "lucky", "congratulations", "claim", "gift", "crypto", "bitcoin",
            "wallet", "invest", "profit", "earn", "money", "cash", "refund", "tax", "irs",
            "billing", "payment", "expired", "blocked", "unauthorized", "verify-account",
            "security-alert", "action-required", "limited-time", "act-now"
        };

        int keywordCount = 0;
        for (String keyword : suspiciousKeywords) {
            if (lowerUrl.contains(keyword)) {
                keywordCount++;
            }
        }

        if (keywordCount > 0) {
            score -= (keywordCount * 2);
            analysis.append(String.format("⚠️ %d suspicious keyword(s) (-%d). ", keywordCount, keywordCount * 2));
        }

        // 5. Length check
        if (url.length() > 100) {
            score -= 1;
            analysis.append("⚠️ Very long URL (-1). ");
        }

        // 6. @ symbol check
        if (lowerUrl.contains("@")) {
            score -= 3;
            analysis.append("⚠️ Contains @ symbol (-3). ");
        }

        // 7. Subdomain count
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            if (host != null) {
                int subdomainCount = host.split("\\.").length - 2;
                if (subdomainCount > 3) {
                    score -= 2;
                    analysis.append("⚠️ Too many subdomains (-2). ");
                }
            }
        } catch (Exception ignored) {}

        // 8. Hex encoding check
        if (lowerUrl.matches(".*%[0-9a-f]{2}.*")) {
            score -= 2;
            analysis.append("⚠️ Suspicious encoding detected (-2). ");
        }

        // 9. Multiple slashes
        if (lowerUrl.indexOf("//", 8) != -1) {
            score -= 2;
            analysis.append("⚠️ Suspicious redirects (-2). ");
        }

        // 10. Suspicious TLDs
        String[] suspiciousTlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click"};
        for (String tld : suspiciousTlds) {
            if (lowerUrl.endsWith(tld)) {
                score -= 3;
                analysis.append("⚠️ Suspicious TLD (-3). ");
                break;
            }
        }

        // Final result
        String result;
        if (score >= 0) {
            result = "✅ Heuristics: SAFE (Score: " + score + ") - " + analysis;
        } else {
            result = "⚠️ Heuristics: SUSPICIOUS (Score: " + score + ") - " + analysis;
        }

        return result;
    }

    private boolean determineOverallSafety(String vtResult, String gsbResult, String heuristicResult) {
        // If any service detects a threat, mark as unsafe
        if (vtResult.contains("⚠️") || vtResult.contains("❌") ||
            gsbResult.contains("⚠️") || gsbResult.contains("❌") ||
            heuristicResult.contains("⚠️")) {
            return false;
        }
        return true;
    }
}