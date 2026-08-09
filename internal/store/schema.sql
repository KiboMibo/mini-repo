-- role/disabled добавлены T18. Для БД, созданной до T18, те же колонки с теми
-- же умолчаниями досоздаёт migrateUsers в store.Open: CREATE TABLE IF NOT
-- EXISTS существующую таблицу не трогает. Менять умолчания надо в обоих местах.
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'admin',
  disabled      INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS apps (
  id                         INTEGER PRIMARY KEY,
  name                       TEXT NOT NULL UNIQUE,
  description                TEXT NOT NULL DEFAULT '',
  latest_override_version_id INTEGER REFERENCES versions(id) ON DELETE SET NULL,
  created_at                 TEXT NOT NULL DEFAULT (datetime('now'))
);
-- platform добавлена T24; для БД, созданной раньше, ту же колонку с тем же
-- умолчанием досоздаёт migrateVersions в store.Open. Как и с users: менять
-- умолчание надо в обоих местах.
CREATE TABLE IF NOT EXISTS versions (
  id         INTEGER PRIMARY KEY,
  app_id     INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  version    TEXT NOT NULL,          -- канонический semver без префикса v
  filename   TEXT NOT NULL,          -- basename оригинального файла
  size_bytes INTEGER NOT NULL,
  sha256     TEXT NOT NULL,          -- hex, нижний регистр
  platform   TEXT NOT NULL DEFAULT '', -- "os/arch", "any" или "" (неизвестно)
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(app_id, version)
);
CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL
);
