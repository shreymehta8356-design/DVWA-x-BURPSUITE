-- ============================================================================
--  DVWA x BURPSUITE
--  Offline Web Application Security Assessment, Evidence & Reporting Platform
--  Database schema  --  MySQL 8.0 / MariaDB 10.4+  (XAMPP)
--
--  Import:  mysql -u root -p < database/schema.sql
--       or: phpMyAdmin > Import > schema.sql
-- ============================================================================

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

CREATE DATABASE IF NOT EXISTS `dvwa_burp_platform`
  DEFAULT CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE `dvwa_burp_platform`;

-- ---------------------------------------------------------------------------
-- 1. IDENTITY, ACCESS CONTROL AND PLATFORM CONFIGURATION
-- ---------------------------------------------------------------------------

DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id`                  INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `username`            VARCHAR(64)  NOT NULL,
  `full_name`           VARCHAR(120) NOT NULL,
  `email`               VARCHAR(160) NULL,
  `password_hash`       VARCHAR(255) NOT NULL,
  `role`                VARCHAR(20)  NOT NULL DEFAULT 'analyst',
  `is_active`           TINYINT(1)   NOT NULL DEFAULT 1,
  `must_change_password` TINYINT(1)  NOT NULL DEFAULT 0,
  `failed_attempts`     INT          NOT NULL DEFAULT 0,
  `locked_until`        DATETIME     NULL,
  `last_login_at`       DATETIME     NULL,
  `last_login_ip`       VARCHAR(45)  NULL,
  `created_at`          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_users_username` (`username`),
  KEY `ix_users_role` (`role`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

DROP TABLE IF EXISTS `login_attempts`;
CREATE TABLE `login_attempts` (
  `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `username`    VARCHAR(64)  NOT NULL,
  `ip_address`  VARCHAR(45)  NOT NULL,
  `successful`  TINYINT(1)   NOT NULL DEFAULT 0,
  `user_agent`  VARCHAR(255) NULL,
  `created_at`  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `ix_attempt_user_time` (`username`, `created_at`),
  KEY `ix_attempt_ip_time` (`ip_address`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

DROP TABLE IF EXISTS `settings`;
CREATE TABLE `settings` (
  `skey`        VARCHAR(80)  NOT NULL,
  `svalue`      TEXT         NULL,
  `value_type`  VARCHAR(16)  NOT NULL DEFAULT 'string',
  `description` VARCHAR(255) NULL,
  `updated_by`  INT UNSIGNED NULL,
  `updated_at`  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`skey`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- 2. ASSESSMENT AND SCOPE
-- ---------------------------------------------------------------------------

DROP TABLE IF EXISTS `assessments`;
CREATE TABLE `assessments` (
  `id`               INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `ref_code`         VARCHAR(32)  NOT NULL,
  `title`            VARCHAR(200) NOT NULL,
  `target_name`      VARCHAR(160) NOT NULL,
  `target_base_url`  VARCHAR(255) NOT NULL,
  `target_type`      VARCHAR(40)  NOT NULL DEFAULT 'dvwa',
  `environment`      VARCHAR(40)  NOT NULL DEFAULT 'local_lab',
  `methodology`      VARCHAR(120) NOT NULL DEFAULT 'OWASP WSTG v4.2',
  `classification`   VARCHAR(40)  NOT NULL DEFAULT 'INTERNAL',
  `objective`        TEXT         NULL,
  `constraints`      TEXT         NULL,
  `rules_of_engagement` TEXT      NULL,
  `status`           VARCHAR(30)  NOT NULL DEFAULT 'draft',
  `start_date`       DATE         NULL,
  `end_date`         DATE         NULL,
  `lead_analyst_id`  INT UNSIGNED NULL,
  `created_by`       INT UNSIGNED NULL,
  `created_at`       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_assessment_ref` (`ref_code`),
  KEY `ix_assessment_status` (`status`),
  CONSTRAINT `fk_assessment_lead` FOREIGN KEY (`lead_analyst_id`) REFERENCES `users`(`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_assessment_creator` FOREIGN KEY (`created_by`) REFERENCES `users`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

DROP TABLE IF EXISTS `scope_items`;
CREATE TABLE `scope_items` (
  `id`            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `assessment_id` INT UNSIGNED NOT NULL,
  `item_type`     VARCHAR(30)  NOT NULL DEFAULT 'url',
  `value`         VARCHAR(255) NOT NULL,
  `in_scope`      TINYINT(1)   NOT NULL DEFAULT 1,
  `notes`         VARCHAR(255) NULL,
  `created_at`    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `ix_scope_assessment` (`assessment_id`),
  CONSTRAINT `fk_scope_assessment` FOREIGN KEY (`assessment_id`) REFERENCES `assessments`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- 3. PREDEFINED SECURITY CHECK CATALOGUE
-- ---------------------------------------------------------------------------

DROP TABLE IF EXISTS `test_catalog`;
CREATE TABLE `test_catalog` (
  `id`                 INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `code`               VARCHAR(32)  NOT NULL,
  `title`              VARCHAR(200) NOT NULL,
  `category`           VARCHAR(80)  NOT NULL,
  `owasp_top10`        VARCHAR(80)  NULL,
  `cwe_id`             VARCHAR(20)  NULL,
  `description`        TEXT         NULL,
  `test_objective`     TEXT         NULL,
  `test_steps`         TEXT         NULL,
  `tools_hint`         VARCHAR(255) NULL,
  `expected_secure_behaviour` TEXT  NULL,
  `default_likelihood` TINYINT      NOT NULL DEFAULT 3,
  `default_impact`     TINYINT      NOT NULL DEFAULT 3,
  `default_cvss_vector` VARCHAR(120) NULL,
  `dvwa_module`        VARCHAR(60)  NULL,
  `is_active`          TINYINT(1)   NOT NULL DEFAULT 1,
  `created_at`         DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_catalog_code` (`code`),
  KEY `ix_catalog_category` (`category`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- 4. TEST EXECUTION AND RESULTS
-- ---------------------------------------------------------------------------

DROP TABLE IF EXISTS `assessment_tests`;
CREATE TABLE `assessment_tests` (
  `id`               INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `assessment_id`    INT UNSIGNED NOT NULL,
  `catalog_id`       INT UNSIGNED NOT NULL,
  `sequence`         INT          NOT NULL DEFAULT 0,
  `status`           VARCHAR(24)  NOT NULL DEFAULT 'pending',
  `observation`      TEXT         NULL,
  `request_snippet`  TEXT         NULL,
  `response_snippet` TEXT         NULL,
  `payload_used`     TEXT         NULL,
  `dvwa_security_level` VARCHAR(16) NULL,
  `tested_by`        INT UNSIGNED NULL,
  `tested_at`        DATETIME     NULL,
  `review_status`    VARCHAR(20)  NOT NULL DEFAULT 'unreviewed',
  `reviewed_by`      INT UNSIGNED NULL,
  `reviewed_at`      DATETIME     NULL,
  `review_note`      VARCHAR(500) NULL,
  `ai_category`      VARCHAR(80)  NULL,
  `ai_confidence`    DECIMAL(6,4) NULL,
  `ai_engine`        VARCHAR(40)  NULL,
  `created_at`       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_test_assessment_catalog` (`assessment_id`, `catalog_id`),
  KEY `ix_test_status` (`assessment_id`, `status`),
  CONSTRAINT `fk_test_assessment` FOREIGN KEY (`assessment_id`) REFERENCES `assessments`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_test_catalog` FOREIGN KEY (`catalog_id`) REFERENCES `test_catalog`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- 5. RISK MODEL  (transparent, admin-editable, versioned by rule text)
-- ---------------------------------------------------------------------------

DROP TABLE IF EXISTS `risk_matrix`;
CREATE TABLE `risk_matrix` (
  `id`          INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `likelihood`  TINYINT      NOT NULL,
  `impact`      TINYINT      NOT NULL,
  `score`       TINYINT      NOT NULL,
  `band`        VARCHAR(16)  NOT NULL,
  `colour`      VARCHAR(16)  NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_matrix_cell` (`likelihood`, `impact`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

DROP TABLE IF EXISTS `severity_sla`;
CREATE TABLE `severity_sla` (
  `severity`     VARCHAR(16) NOT NULL,
  `sla_days`     INT         NOT NULL,
  `rank`         TINYINT     NOT NULL,
  `description`  VARCHAR(255) NULL,
  PRIMARY KEY (`severity`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- 6. FINDINGS
-- ---------------------------------------------------------------------------

DROP TABLE IF EXISTS `findings`;
CREATE TABLE `findings` (
  `id`                 INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `assessment_id`      INT UNSIGNED NOT NULL,
  `ref_code`           VARCHAR(32)  NOT NULL,
  `test_id`            INT UNSIGNED NULL,
  `title`              VARCHAR(220) NOT NULL,
  `vuln_class`         VARCHAR(80)  NULL,
  `cwe_id`             VARCHAR(20)  NULL,
  `owasp_top10`        VARCHAR(80)  NULL,
  `affected_component` VARCHAR(200) NULL,
  `affected_url`       VARCHAR(255) NULL,
  `description`        TEXT         NULL,
  `impact_narrative`   TEXT         NULL,
  `reproduction_steps` TEXT         NULL,
  `likelihood`         TINYINT      NOT NULL DEFAULT 3,
  `impact`             TINYINT      NOT NULL DEFAULT 3,
  `matrix_score`       TINYINT      NULL,
  `matrix_band`        VARCHAR(16)  NULL,
  `cvss_vector`        VARCHAR(120) NULL,
  `cvss_base_score`    DECIMAL(3,1) NULL,
  `cvss_band`          VARCHAR(16)  NULL,
  `severity`           VARCHAR(16)  NOT NULL DEFAULT 'medium',
  `severity_source`    VARCHAR(16)  NOT NULL DEFAULT 'matrix',
  `severity_rationale` TEXT         NULL,
  `confidence`         VARCHAR(16)  NOT NULL DEFAULT 'confirmed',
  `status`             VARCHAR(24)  NOT NULL DEFAULT 'open',
  `duplicate_of`       INT UNSIGNED NULL,
  `similarity_score`   DECIMAL(6,4) NULL,
  `ai_assisted_fields` TEXT         NULL,
  `created_by`         INT UNSIGNED NULL,
  `verified_by`        INT UNSIGNED NULL,
  `closed_at`          DATETIME     NULL,
  `created_at`         DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`         DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_finding_ref` (`assessment_id`, `ref_code`),
  KEY `ix_finding_sev` (`assessment_id`, `severity`),
  KEY `ix_finding_status` (`assessment_id`, `status`),
  CONSTRAINT `fk_finding_assessment` FOREIGN KEY (`assessment_id`) REFERENCES `assessments`(`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_finding_test` FOREIGN KEY (`test_id`) REFERENCES `assessment_tests`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- 7. EVIDENCE AND CHAIN OF CUSTODY
-- ---------------------------------------------------------------------------

DROP TABLE IF EXISTS `evidence`;
CREATE TABLE `evidence` (
  `id`               INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `assessment_id`    INT UNSIGNED NOT NULL,
  `test_id`          INT UNSIGNED NULL,
  `finding_id`       INT UNSIGNED NULL,
  `retest_id`        INT UNSIGNED NULL,
  `evidence_type`    VARCHAR(30)  NOT NULL DEFAULT 'note',
  `title`            VARCHAR(200) NOT NULL,
  `description`      TEXT         NULL,
  `content_text`     MEDIUMTEXT   NULL,
  `stored_name`      VARCHAR(160) NULL,
  `original_name`    VARCHAR(200) NULL,
  `mime_type`        VARCHAR(120) NULL,
  `file_size`        INT UNSIGNED NULL,
  `sha256`           CHAR(64)     NOT NULL,
  `is_redacted`      TINYINT(1)   NOT NULL DEFAULT 0,
  `redaction_summary` VARCHAR(500) NULL,
  `captured_at`      DATETIME     NULL,
  `collected_by`     INT UNSIGNED NULL,
  `created_at`       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `ix_evidence_assessment` (`assessment_id`),
  KEY `ix_evidence_test` (`test_id`),
  KEY `ix_evidence_finding` (`finding_id`),
  KEY `ix_evidence_hash` (`sha256`),
  CONSTRAINT `fk_evidence_assessment` FOREIGN KEY (`assessment_id`) REFERENCES `assessments`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

DROP TABLE IF EXISTS `evidence_custody`;
CREATE TABLE `evidence_custody` (
  `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `evidence_id` INT UNSIGNED NOT NULL,
  `action`      VARCHAR(24)  NOT NULL,
  `actor_id`    INT UNSIGNED NULL,
  `actor_name`  VARCHAR(120) NULL,
  `actor_ip`    VARCHAR(45)  NULL,
  `note`        VARCHAR(400) NULL,
  `created_at`  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `ix_custody_evidence` (`evidence_id`),
  CONSTRAINT `fk_custody_evidence` FOREIGN KEY (`evidence_id`) REFERENCES `evidence`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- 8. REMEDIATION AND RETEST
-- ---------------------------------------------------------------------------

DROP TABLE IF EXISTS `remediation`;
CREATE TABLE `remediation` (
  `id`                 INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `finding_id`         INT UNSIGNED NOT NULL,
  `recommendation`     TEXT         NULL,
  `secure_code_example` TEXT        NULL,
  `reference_links`    TEXT         NULL,
  `effort`             VARCHAR(16)  NOT NULL DEFAULT 'medium',
  `priority`           TINYINT      NOT NULL DEFAULT 3,
  `owner_name`         VARCHAR(120) NULL,
  `owner_team`         VARCHAR(120) NULL,
  `due_date`           DATE         NULL,
  `sla_days`           INT          NULL,
  `status`             VARCHAR(24)  NOT NULL DEFAULT 'not_started',
  `notes`              TEXT         NULL,
  `ai_assisted`        TINYINT(1)   NOT NULL DEFAULT 0,
  `created_by`         INT UNSIGNED NULL,
  `created_at`         DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`         DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_remediation_finding` (`finding_id`),
  CONSTRAINT `fk_remediation_finding` FOREIGN KEY (`finding_id`) REFERENCES `findings`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

DROP TABLE IF EXISTS `remediation_log`;
CREATE TABLE `remediation_log` (
  `id`             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `remediation_id` INT UNSIGNED NOT NULL,
  `from_status`    VARCHAR(24)  NULL,
  `to_status`      VARCHAR(24)  NOT NULL,
  `note`           VARCHAR(500) NULL,
  `actor_id`       INT UNSIGNED NULL,
  `actor_name`     VARCHAR(120) NULL,
  `created_at`     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `ix_remlog_rem` (`remediation_id`),
  CONSTRAINT `fk_remlog_rem` FOREIGN KEY (`remediation_id`) REFERENCES `remediation`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

DROP TABLE IF EXISTS `retests`;
CREATE TABLE `retests` (
  `id`                INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `finding_id`        INT UNSIGNED NOT NULL,
  `round_no`          INT          NOT NULL DEFAULT 1,
  `retest_date`       DATE         NULL,
  `tester_id`         INT UNSIGNED NULL,
  `method`            VARCHAR(200) NULL,
  `result`            VARCHAR(24)  NOT NULL DEFAULT 'not_fixed',
  `observation`       TEXT         NULL,
  `residual_severity` VARCHAR(16)  NULL,
  `closes_finding`    TINYINT(1)   NOT NULL DEFAULT 0,
  `created_at`        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_retest_round` (`finding_id`, `round_no`),
  CONSTRAINT `fk_retest_finding` FOREIGN KEY (`finding_id`) REFERENCES `findings`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- 9. REPORTING
-- ---------------------------------------------------------------------------

DROP TABLE IF EXISTS `reports`;
CREATE TABLE `reports` (
  `id`             INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `assessment_id`  INT UNSIGNED NOT NULL,
  `ref_code`       VARCHAR(40)  NOT NULL,
  `report_type`    VARCHAR(20)  NOT NULL DEFAULT 'full',
  `version`        VARCHAR(16)  NOT NULL DEFAULT '1.0',
  `title`          VARCHAR(220) NOT NULL,
  `classification` VARCHAR(40)  NOT NULL DEFAULT 'INTERNAL',
  `status`         VARCHAR(16)  NOT NULL DEFAULT 'draft',
  `executive_summary` TEXT      NULL,
  `snapshot_json`  LONGTEXT     NULL,
  `stored_name`    VARCHAR(160) NULL,
  `sha256`         CHAR(64)     NULL,
  `generated_by`   INT UNSIGNED NULL,
  `generated_at`   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `ix_report_assessment` (`assessment_id`),
  CONSTRAINT `fk_report_assessment` FOREIGN KEY (`assessment_id`) REFERENCES `assessments`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- 10. BURP SUITE IMPORT
-- ---------------------------------------------------------------------------

DROP TABLE IF EXISTS `burp_imports`;
CREATE TABLE `burp_imports` (
  `id`             INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `assessment_id`  INT UNSIGNED NOT NULL,
  `filename`       VARCHAR(200) NOT NULL,
  `file_sha256`    CHAR(64)     NOT NULL,
  `issue_count`    INT          NOT NULL DEFAULT 0,
  `imported_count` INT          NOT NULL DEFAULT 0,
  `burp_version`   VARCHAR(40)  NULL,
  `export_time`    VARCHAR(60)  NULL,
  `imported_by`    INT UNSIGNED NULL,
  `created_at`     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `ix_burpimport_assessment` (`assessment_id`),
  CONSTRAINT `fk_burpimport_assessment` FOREIGN KEY (`assessment_id`) REFERENCES `assessments`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

DROP TABLE IF EXISTS `burp_issues`;
CREATE TABLE `burp_issues` (
  `id`                  INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `import_id`           INT UNSIGNED NOT NULL,
  `assessment_id`       INT UNSIGNED NOT NULL,
  `serial_number`       VARCHAR(64)  NULL,
  `issue_type`          VARCHAR(40)  NULL,
  `name`                VARCHAR(220) NOT NULL,
  `host`                VARCHAR(200) NULL,
  `path`                VARCHAR(255) NULL,
  `location`            VARCHAR(255) NULL,
  `burp_severity`       VARCHAR(24)  NULL,
  `burp_confidence`     VARCHAR(24)  NULL,
  `issue_background`    TEXT         NULL,
  `issue_detail`        TEXT         NULL,
  `remediation_background` TEXT      NULL,
  `request_text`        MEDIUMTEXT   NULL,
  `response_text`       MEDIUMTEXT   NULL,
  `mapped_catalog_id`   INT UNSIGNED NULL,
  `mapped_finding_id`   INT UNSIGNED NULL,
  `ai_category`         VARCHAR(80)  NULL,
  `ai_confidence`       DECIMAL(6,4) NULL,
  `action`              VARCHAR(20)  NOT NULL DEFAULT 'pending',
  `created_at`          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `ix_burpissue_import` (`import_id`),
  KEY `ix_burpissue_assessment` (`assessment_id`),
  CONSTRAINT `fk_burpissue_import` FOREIGN KEY (`import_id`) REFERENCES `burp_imports`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- 11. AI GOVERNANCE  (every model invocation is recorded and reviewable)
-- ---------------------------------------------------------------------------

DROP TABLE IF EXISTS `ai_runs`;
CREATE TABLE `ai_runs` (
  `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `assessment_id` INT UNSIGNED NULL,
  `entity_type`   VARCHAR(40)  NULL,
  `entity_id`     INT UNSIGNED NULL,
  `task`          VARCHAR(30)  NOT NULL,
  `engine`        VARCHAR(30)  NOT NULL,
  `model_name`    VARCHAR(80)  NULL,
  `input_hash`    CHAR(64)     NULL,
  `input_excerpt` VARCHAR(500) NULL,
  `output`        MEDIUMTEXT   NULL,
  `confidence`    DECIMAL(6,4) NULL,
  `latency_ms`    INT          NULL,
  `accepted`      TINYINT(1)   NULL,
  `actor_id`      INT UNSIGNED NULL,
  `created_at`    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `ix_airun_entity` (`entity_type`, `entity_id`),
  KEY `ix_airun_task` (`task`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

DROP TABLE IF EXISTS `ai_training_data`;
CREATE TABLE `ai_training_data` (
  `id`         INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `text`       TEXT         NOT NULL,
  `label`      VARCHAR(80)  NOT NULL,
  `source`     VARCHAR(20)  NOT NULL DEFAULT 'seed',
  `is_active`  TINYINT(1)   NOT NULL DEFAULT 1,
  `created_by` INT UNSIGNED NULL,
  `created_at` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `ix_training_label` (`label`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- 12. TAMPER-EVIDENT AUDIT TRAIL  (hash-chained)
-- ---------------------------------------------------------------------------

DROP TABLE IF EXISTS `audit_log`;
CREATE TABLE `audit_log` (
  `id`             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `actor_id`       INT UNSIGNED NULL,
  `actor_username` VARCHAR(64)  NULL,
  `actor_ip`       VARCHAR(45)  NULL,
  `action`         VARCHAR(60)  NOT NULL,
  `entity_type`    VARCHAR(40)  NULL,
  `entity_id`      INT UNSIGNED NULL,
  `assessment_id`  INT UNSIGNED NULL,
  `detail`         TEXT         NULL,
  `prev_hash`      CHAR(64)     NULL,
  `row_hash`       CHAR(64)     NOT NULL,
  `created_at`     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `ix_audit_entity` (`entity_type`, `entity_id`),
  KEY `ix_audit_assessment` (`assessment_id`),
  KEY `ix_audit_time` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET FOREIGN_KEY_CHECKS = 1;
