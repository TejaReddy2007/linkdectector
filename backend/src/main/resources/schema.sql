-- Users table
CREATE TABLE IF NOT EXISTS users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Scanned links table
CREATE TABLE IF NOT EXISTS scanned_links (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    url VARCHAR(2048) NOT NULL,
    safe BOOLEAN NOT NULL,
    virus_total_result TEXT,
    google_safe_browsing_result TEXT,
    heuristic_result TEXT,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Community reports table
CREATE TABLE IF NOT EXISTS community_reports (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    url VARCHAR(2048) NOT NULL,
    status VARCHAR(20) NOT NULL,
    comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes for performance
CREATE INDEX idx_scanned_links_user_id ON scanned_links(user_id);
CREATE INDEX idx_scanned_links_scanned_at ON scanned_links(scanned_at DESC);
CREATE INDEX idx_community_reports_user_id ON community_reports(user_id);
CREATE INDEX idx_community_reports_created_at ON community_reports(created_at DESC);

