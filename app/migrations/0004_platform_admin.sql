ALTER TABLE users ADD COLUMN is_platform_admin INTEGER NOT NULL DEFAULT 0
CHECK(is_platform_admin IN (0, 1));
