CREATE DATABASE IF NOT EXISTS digital_signin_auditor
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE digital_signin_auditor;

CREATE TABLE IF NOT EXISTS users (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  full_name VARCHAR(150) NOT NULL,
  employee_id VARCHAR(60) NOT NULL,
  email VARCHAR(254) NOT NULL,
  password_hash VARBINARY(60) NOT NULL,
  department VARCHAR(120) NOT NULL,
  role ENUM('staff', 'administrator') NOT NULL DEFAULT 'staff',
  face_model VARCHAR(40) NOT NULL,
  face_template MEDIUMBLOB NOT NULL,
  biometric_consent_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_employee_id (employee_id),
  UNIQUE KEY uq_users_email (email)
);

CREATE TABLE IF NOT EXISTS attendance_records (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id BIGINT UNSIGNED NOT NULL,
  sign_in_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  sign_out_at TIMESTAMP NULL DEFAULT NULL,
  PRIMARY KEY (id),
  KEY ix_attendance_user_sign_in (user_id, sign_in_at),
  KEY ix_attendance_open_session (user_id, sign_out_at),
  CONSTRAINT fk_attendance_user
    FOREIGN KEY (user_id) REFERENCES users (id)
    ON DELETE CASCADE
);
