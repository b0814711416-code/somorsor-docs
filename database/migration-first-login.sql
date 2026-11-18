-- ============================================================
-- Migration: เข้าระบบครั้งแรกด้วยรหัส 123456 แล้วบังคับเปลี่ยนรหัสผ่าน
-- (รันใน Neon แล้วเมื่อ 2026-11-18)
-- หมายเหตุ: คอลัมน์ email ใช้เก็บ "ชื่อผู้ใช้" ด้วย (เช่น chaiso01)
-- ============================================================

-- 1) flag บังคับเปลี่ยนรหัสผ่าน
ALTER TABLE admin_users
  ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE;

-- 2) บัญชีบุคลากรเดิม: chaiso0X@school.ac.th → chaiso0X
--    รีเซ็ตรหัสเป็น 123456 (bcrypt) + บังคับเปลี่ยนเมื่อเข้าครั้งถัดไป
UPDATE admin_users
SET email = split_part(email, '@', 1),
    password_hash = '$2a$10$ZCiAviG0wlEAfQnDoB9t2O1NJXtSJxnEG.6bRhPxcRxx3Q5K40B7.',
    must_change_password = TRUE
WHERE email IN ('chaiso01@school.ac.th','chaiso02@school.ac.th','chaiso03@school.ac.th',
                'chaiso04@school.ac.th','chaiso05@school.ac.th','chaiso06@school.ac.th',
                'chaiso07@school.ac.th','chaiso09@school.ac.th');

-- 3) บัญชีผู้ดูแลระบบ: admin@school.ac.th → admin
--    รหัสผ่านจริงตั้งตรงใน Neon แล้ว — ไม่เก็บ hash ไว้ใน repo
-- UPDATE admin_users SET email = 'admin', password_hash = '<bcrypt hash>', role = 'admin',
--   must_change_password = FALSE WHERE email = 'admin@school.ac.th';
