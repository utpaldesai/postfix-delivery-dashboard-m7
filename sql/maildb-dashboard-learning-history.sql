-- Dashboard-owned learning history. This table does not alter SpamAssassin Bayes internals.
CREATE TABLE IF NOT EXISTS maildb.dashboard_learning_history (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    quarantine_id VARCHAR(255) NOT NULL,
    message_id VARCHAR(255) NULL,
    sender VARCHAR(320) NULL,
    recipient VARCHAR(320) NULL,
    learning_type ENUM('SPAM','HAM') NOT NULL,
    learned_by VARCHAR(128) NOT NULL,
    client_ip VARCHAR(64) NULL,
    learned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sa_learn_rc INT NOT NULL,
    examined_count INT NULL,
    learned_count INT NULL,
    source_sha256 CHAR(64) NULL,
    sa_learn_output TEXT NULL,
    PRIMARY KEY (id),
    KEY idx_qid (quarantine_id),
    KEY idx_msgid (message_id),
    KEY idx_learning (learning_type, learned_at),
    KEY idx_sender (sender),
    KEY idx_learned_at (learned_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Grant only the new dashboard-owned table to the existing SpamAssassin dashboard DB user.
GRANT SELECT, INSERT ON maildb.dashboard_learning_history TO 'spam'@'127.0.0.1';
