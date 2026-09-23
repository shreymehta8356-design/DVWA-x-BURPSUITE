-- ============================================================================
--  DVWA x BURPSUITE  --  Default accounts
--
--  !! CHANGE EVERY PASSWORD BELOW AFTER THE FIRST LOGIN !!
--  Each account is flagged must_change_password = 1.
--
--  username   password             role
--  ---------  -------------------  -------------------------------------------
--  admin      Admin@DVWA2026       admin     - full control, users, settings, AI
--  lead       Lead@DVWA2026        lead      - owns assessments, finalises reports
--  analyst    Analyst@DVWA2026     analyst   - executes tests, records evidence
--  reviewer   Review@DVWA2026      reviewer  - read only plus peer review sign-off
--
--  To create additional accounts safely use:  php tools/create_user.php
-- ============================================================================

SET NAMES utf8mb4;
USE `dvwa_burp_platform`;

DELETE FROM `users`;
INSERT INTO `users` (`username`,`full_name`,`email`,`password_hash`,`role`,`is_active`,`must_change_password`) VALUES
('admin','Platform Administrator','admin@localhost',
 '$2y$12$vPNYE3qITS3cYGwXTu6wU.O6wOJG6G3NNDo2Upwnhp6EMMiumgrAu','admin',1,1),
('lead','Lead Security Analyst','lead@localhost',
 '$2y$12$6KkWZrRVZiTmCNOkhk7nrOk5/iN0xG/6JE84eaYXN594OJhnZhW6O','lead',1,1),
('analyst','Security Analyst','analyst@localhost',
 '$2y$12$iln2hl2j4LN9fZXwvQuGpeqxEz2p1fTAKtoRE6zfGHC0MwC9v0Lfe','analyst',1,1),
('reviewer','Peer Reviewer','reviewer@localhost',
 '$2y$12$hSG/xYvky8JrF95Lod7ACO2uIhgDelJGXxcia3xj5.V91De99UQ1a','reviewer',1,1);
