-- Run locally as a database administrator. Replace the password before execution.
-- This creates a separate schema; never reuse the old Manager's application tables.
CREATE DATABASE IF NOT EXISTS servicegateway CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'servicegateway'@'127.0.0.1' IDENTIFIED BY 'REPLACE_WITH_A_STRONG_RANDOM_PASSWORD';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, REFERENCES ON servicegateway.* TO 'servicegateway'@'127.0.0.1';
-- Runtime can use a separate least-privilege user after migrations:
-- GRANT SELECT, INSERT, UPDATE, DELETE ON servicegateway.* TO 'servicegateway_runtime'@'127.0.0.1';
