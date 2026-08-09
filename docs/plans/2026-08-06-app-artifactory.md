# План: app_artifactory — репозиторий бинарников приложений

- **Дата:** 2026-08-06
- **Статус:** в работе
- **Цель одним предложением:** веб-сервис на Go, в котором можно заводить приложения, загружать их версии-бинарники в `/opt/apps/{app}/{version}/`, сверять SHA-256, и скачивать по прямым стабильным ссылкам (конкретная версия и `latest`) через UI и JSON API.

## Контекст

Проект с нуля в пустом репозитории. Решения приняты с пользователем:

- **Стек:** Go (stdlib `net/http` с паттернами роутинга Go 1.22+, `html/template`), SQLite через чистый Go-драйвер `github.com/ncruces/go-sqlite3` (WASM-сборка SQLite поверх wazero, без CGO), пароли — `golang.org/x/crypto/bcrypt`, semver — `github.com/Masterminds/semver/v3`.
- **UI:** серверные HTML-страницы (шаблоны embed-ятся в бинарник).
- **Доступ:** заливка и управление — по логину/паролю (сессионная кука в UI); скачивание и JSON API — HTTP Basic Auth с теми же учётками. Анонимного доступа нет.
- **Хеш:** при загрузке SHA-256 опционален — если передан, сервер сверяет и отклоняет несовпадение; сервер всегда считает и хранит хеш сам.
- **Latest:** автоматически максимальная semver-версия; можно вручную закрепить конкретную версию (override) и снять закрепление.
- **Метаданные:** SQLite; **бинарники:** диск, `{data_dir}/{app}/{version}/{filename}` (по умолчанию `/opt/apps`).
- **Деплой:** один бинарник + systemd unit.

## Цель и критерии готовности

- `go build ./...` и `go test ./...` зелёные; бинарник `apprepo` собирается.
- Через UI: логин, создание приложения, загрузка версии с файлом (с хешем и без), список версий, назначение/снятие latest-override.
- `GET /download/{app}/{version}` и `GET /download/{app}/latest` под Basic Auth отдают файл с корректным `Content-Disposition` и заголовком `X-Checksum-Sha256`.
- JSON API отдаёт списки приложений/версий с полями `download_url` (абсолютная прямая ссылка), `sha256`, `is_latest`; `PUT /api/apps/{name}/versions/{version}` заливает бинарник из скрипта/CI.
- Загрузка с неверным клиентским SHA-256 отклоняется, файл не сохраняется.
- `apprepo user add <name>` создаёт пользователя; без единого пользователя сервис подсказывает, как его создать.
- Есть README (запуск, конфиг, примеры curl) и systemd unit.

## В скоупе / вне скоупа

**В скоупе:** всё перечисленное выше.

**Вне скоупа (осознанно):** удаление приложений и версий; роли/права (все залогиненные равны); квоты и лимиты места; TLS-терминация (предполагается reverse-proxy); докеризация; веб-управление пользователями (только CLI); докачка/resumable upload; хранение нескольких файлов на версию (одна версия — один файл).

## Архитектурные решения

1. **Один бинарник, stdlib-роутер.** Никаких web-фреймворков: `http.ServeMux` Go 1.22+ умеет методы и path-параметры. Меньше зависимостей — проще деплой и аудит.
2. **github.com/ncruces/go-sqlite3** (пин v0.29.0, пакеты `/driver` + `/embed`, имя драйвера в `sql.Open` — `"sqlite3"`) — чистый Go без CGO (SQLite скомпилирован в WASM, исполняется wazero), кросс-компиляция свободная. Причина замены исходного выбора (modernc.org/sqlite): egress-политика облачной песочницы разработки допускает только github.com, а транзитивные зависимости modernc живут на заблокированном gitlab.com; ncruces + wazero + зеркала golang/* целиком на GitHub — проверено рабочим прототипом. В `go.mod` — `replace` официальных зеркал (`golang.org/x/sys => github.com/golang/sys` и т.п.); в среде с нормальной сетью их можно удалить. Пул stdlib `database/sql`, `PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000`.
3. **Загрузка через temp+rename:** файл стримится в `{data_dir}/.tmp/…` с одновременным подсчётом SHA-256; при несовпадении с клиентским хешем temp удаляется и возвращается 422; при успехе — `os.MkdirAll` + `os.Rename` (атомарно в пределах ФС) и вставка строки в БД. Файл на диске без строки в БД невозможен только наоборот: сначала файл, потом запись; при ошибке вставки файл подчищается.
4. **Latest =** override, если задан, иначе максимум по semver среди версий приложения. Резолвится на лету (версий у приложения немного), отдельного поля «latest» в versions нет — нечему рассинхронизироваться.
5. **Сессии в SQLite** (таблица sessions, токен — 32 случайных байта hex, TTL 7 суток) — переживают рестарт сервиса.
6. **Валидация имён обязательна до касания ФС:** имя приложения `^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$` и не равно `latest`; версия — валидный semver (допускается префикс `v`, хранится каноничный вид без `v`); имя файла — только basename, без `/`, `\\`, `..`, не пустое, ≤255 байт. Это единственная защита от path traversal — она в одном пакете `internal/naming`, все входы идут через неё.
7. **Шаблоны и статика — `embed.FS`**, бинарник самодостаточен.
8. **Все ошибки API — JSON** `{"error":"<code>","message":"<текст>"}`; UI — человекочитаемые страницы/флеш-сообщения.

## Контракты

### Схема БД (фиксирована, `internal/store/schema.sql`)

```sql
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS apps (
  id                         INTEGER PRIMARY KEY,
  name                       TEXT NOT NULL UNIQUE,
  description                TEXT NOT NULL DEFAULT '',
  latest_override_version_id INTEGER REFERENCES versions(id) ON DELETE SET NULL,
  created_at                 TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS versions (
  id         INTEGER PRIMARY KEY,
  app_id     INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  version    TEXT NOT NULL,          -- канонический semver без префикса v
  filename   TEXT NOT NULL,          -- basename оригинального файла
  size_bytes INTEGER NOT NULL,
  sha256     TEXT NOT NULL,          -- hex, нижний регистр
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(app_id, version)
);
CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL
);
```

### Раскладка пакетов

```
cmd/apprepo/            main.go — флаги, подкоманды serve (по умолчанию) и user add, wiring
internal/config/        Config{Addr, DataDir, DBPath, BaseURL, MaxUploadBytes} из флагов+env
internal/naming/        ValidateAppName, ValidateVersion, ValidateFilename
internal/store/         Store поверх database/sql + schema.sql
internal/files/         Storage — сохранение/чтение бинарников
internal/auth/          bcrypt, сессии, middleware (Session + Basic)
internal/web/           UI-хендлеры + templates/ (embed)
internal/api/           JSON API + /download/ хендлеры
deploy/                 apprepo.service, пример env-файла
scripts/smoke.sh        сквозной сценарий через curl
```

### Конфигурация (флаг / env, флаг приоритетнее)

| Флаг | Env | Дефолт |
|---|---|---|
| `-addr` | `APPREPO_ADDR` | `:8080` |
| `-data-dir` | `APPREPO_DATA_DIR` | `/opt/apps` |
| `-db` | `APPREPO_DB` | `{data-dir}/apprepo.db` |
| `-base-url` | `APPREPO_BASE_URL` | `http://localhost:8080` |
| `-max-upload` | `APPREPO_MAX_UPLOAD` | `2147483648` (2 GiB) |

### Ключевые сигнатуры

```go
// internal/naming
func ValidateAppName(name string) error                     // ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$ и name != "latest"
func ValidateVersion(v string) (canonical string, err error) // semver, канон без "v"
func ValidateFilename(name string) error                     // basename, без /,\,.., не пусто, ≤255

// internal/store
func Open(path string) (*Store, error)                       // применяет schema.sql и PRAGMA
func (s *Store) CreateUser(username, passwordHash string) error
func (s *Store) GetUser(username string) (*User, error)      // (nil,nil) если нет
func (s *Store) CountUsers() (int, error)
func (s *Store) CreateSession(userID int64, ttl time.Duration) (token string, err error)
func (s *Store) GetSession(token string) (*Session, error)   // (nil,nil) если нет/просрочена (просроченную удаляет)
func (s *Store) DeleteSession(token string) error
func (s *Store) CreateApp(name, description string) (*App, error)         // ErrExists
func (s *Store) GetApp(name string) (*App, error)            // (nil,nil) если нет
func (s *Store) ListApps() ([]*App, error)                   // по name asc
func (s *Store) SetLatestOverride(appID int64, versionID *int64) error    // nil — снять
func (s *Store) CreateVersion(appID int64, version, filename string, size int64, sha256 string) (*Version, error) // ErrExists при дубле версии
func (s *Store) GetVersion(appID int64, version string) (*Version, error)
func (s *Store) ListVersions(appID int64) ([]*Version, error) // semver desc
func (s *Store) DeleteVersion(id int64) error                 // для отката неудачной вставки
func (s *Store) LatestVersion(appID int64) (*Version, error)  // override → он, иначе max semver; (nil,nil) если версий нет
var ErrExists = errors.New("already exists")

// internal/files
type Storage struct{ Root string }                            // Root = data-dir
var ErrHashMismatch = errors.New("sha256 mismatch")
func (st *Storage) Save(app, version, filename string, r io.Reader, wantSHA256 string) (sha256hex string, size int64, err error)
func (st *Storage) Path(app, version, filename string) string // {Root}/{app}/{version}/{filename}
func (st *Storage) Remove(app, version, filename string) error

// internal/auth
func HashPassword(pw string) (string, error)
func CheckPassword(hash, pw string) bool
type Auth struct{ Store *store.Store }
func (a *Auth) RequireSession(next http.Handler) http.Handler // нет сессии → 303 на /login?next=…
func (a *Auth) RequireBasic(next http.Handler) http.Handler   // 401 + WWW-Authenticate: Basic realm="apprepo"
func (a *Auth) CurrentUser(r *http.Request) *store.User       // из контекста после middleware
func (a *Auth) LoginUser(w http.ResponseWriter, username, password string) error // проверка + кука apprepo_session (HttpOnly, SameSite=Lax, Path=/)
func (a *Auth) LogoutUser(w http.ResponseWriter, r *http.Request)

// регистрация роутов
func web.Register(mux *http.ServeMux, st *store.Store, fs *files.Storage, a *auth.Auth, cfg config.Config)
func api.Register(mux *http.ServeMux, st *store.Store, fs *files.Storage, a *auth.Auth, cfg config.Config)
```

### HTTP-маршруты

**UI (сессия, кроме /login):**

| Маршрут | Что |
|---|---|
| `GET /login`, `POST /login` (form: username, password), `POST /logout` | вход/выход |
| `GET /{$}` | список приложений (имя, описание, latest, число версий) |
| `POST /apps` (form: name, description) | создать приложение → 303 на страницу приложения |
| `GET /apps/{name}` | версии (semver desc, с размером/датой/sha256/ссылкой), форма загрузки, управление latest |
| `POST /apps/{name}/versions` (multipart: file, version, sha256 — опц.) | загрузка → 303 обратно; ошибки — на странице |
| `POST /apps/{name}/latest` (form: version — конкретная или `auto`) | закрепить/снять latest |

**Скачивание (Basic Auth):**

| Маршрут | Что |
|---|---|
| `GET /download/{name}/{version}` | файл версии: `Content-Disposition: attachment; filename="{filename}"`, `X-Checksum-Sha256`, `Content-Length` |
| `GET /download/{name}/latest` | то же для latest-версии (отдаёт файл напрямую, не редирект) |

**API (Basic Auth, JSON):**

| Маршрут | Что |
|---|---|
| `GET /api/apps` | `[{name, description, versions_count, latest, created_at}]`, latest — объект версии или null |
| `POST /api/apps` `{name, description}` | 201 + объект приложения; 409 при дубле |
| `GET /api/apps/{name}` | `{name, description, created_at, latest, versions:[…]}` |
| `GET /api/apps/{name}/versions` | список объектов версии |
| `GET /api/apps/{name}/versions/{version}` | объект версии; 404 если нет |
| `GET /api/apps/{name}/latest` | объект latest-версии; 404 если версий нет |
| `PUT /api/apps/{name}/versions/{version}` | тело = сырые байты файла; заголовок `X-Checksum-Sha256` опц.; ~~`?filename=` опц. (дефолт `{name}-{version}`)~~ → **изменено волной 7 (T23): `?filename=` обязателен**, пустой или отсутствующий → 400 `filename_required` (дефолт без расширения ломал скачивание архивов); 201 + объект версии; 409 дубль; 422 несовпадение хеша; 404 нет приложения |
| `POST /api/apps/{name}/latest` `{version: "1.2.3" \| "auto"}` | закрепить/снять latest |

**Объект версии (везде одинаковый):**

```json
{
  "version": "1.2.3",
  "filename": "myapp-linux-amd64",
  "size_bytes": 12345678,
  "sha256": "ab…ef",
  "created_at": "2026-08-06T12:00:00Z",
  "download_url": "{base_url}/download/{app}/1.2.3",
  "is_latest": true
}
```

**Коды ошибок API:** `unauthorized` (401), `not_found` (404), `already_exists` (409), `invalid_name`/`invalid_version`/`invalid_filename`/`validation` (400), `hash_mismatch` (422), `too_large` (413), `internal` (500). *Изменено волной 7 (T23):* добавлен `filename_required` (400).

## Карта задач

| ID | Название | Зависит от | Волна |
|----|----------|------------|-------|
| T1 | Каркас: go.mod, config, naming, скелет main | — | 1 |
| T2 | Слой хранения SQLite | T1 | 2 |
| T3 | Файловое хранилище бинарников | T1 | 2 |
| R2-test | Тесты волны 2 | T2, T3 | 2-ревью |
| F2 | Исправления по R2 | R2-test | 2-ревью |
| T4 | Аутентификация и middleware | T2 | 3 |
| T5 | Веб-UI | T2, T3 | 3 |
| T6 | JSON API + скачивание | T2, T3 | 3 |
| T7 | Интеграция: wiring, CLI, systemd, smoke | T4, T5, T6 | 4 |
| R4-test | Интеграционные тесты волн 3–4 | T7 | 4-ревью |
| R4-sec | Секьюрити-ревью всего кода | T7 | 4-ревью |
| R4-qa | QA-приёмка + документация | T7 | 4-ревью |
| F4 | Исправления по R4 | R4-* | 4-ревью |

Соразмерность: после волны 1 (каркас без логики) проверочная волна не запускается — нечего проверять, критерий T1 закрывается сборкой. После волны 2 — только тесты (кода UI/API ещё нет, secure/qa смотрели бы на заглушки). Полная тройка — после волны 4 на смерженном целом; волна 3 отдельно не ревьюится, потому что сразу за ней идёт мелкая интеграционная волна 4, и проверять осмысленно уже собранный сервис.

## Задачи

### T1. Каркас проекта

- **Зависит от:** —
- **Волна:** 1
- **Файлы (владеет):** `go.mod`, `go.sum`, `cmd/apprepo/main.go`, `internal/config/config.go`, `internal/naming/naming.go`, `internal/naming/naming_test.go`, `Makefile`, `.gitignore`
- **Скилы:** `/coding-writer`

**Что сделать**
Модуль `apprepo` (Go ≥1.22). Зависимости: `modernc.org/sqlite`, `golang.org/x/crypto`, `github.com/Masterminds/semver/v3`. `internal/config` — парсинг флагов/env по таблице из «Контрактов». `internal/naming` — три валидатора по контракту, с юнит-тестами (traversal, `latest`, префикс `v`, невалидный semver). `cmd/apprepo/main.go` — разбор подкоманд: `serve` (по умолчанию; пока поднимает `http.ServeMux` c одним `GET /healthz` → `200 ok`) и `user add <username>` (пока заглушка с `not implemented`). Makefile: `build`, `test`, `run`. `.gitignore` под Go.

**Критерии приёмки**
- `go build ./...` и `go test ./...` зелёные.
- `go run ./cmd/apprepo -addr :9090` поднимает сервер, `curl :9090/healthz` → `ok`; env `APPREPO_ADDR` работает, флаг приоритетнее.
- `naming`: `ValidateAppName("latest")` и `("../x")` → ошибка; `ValidateVersion("v1.2.3")` → `"1.2.3"`; `ValidateVersion("абв")` → ошибка; `ValidateFilename("a/../b")` → ошибка.

**Проверка**
`go test ./... && go vet ./...`

### T2. Слой хранения SQLite

- **Зависит от:** T1
- **Волна:** 2
- **Файлы (владеет):** `internal/store/store.go`, `internal/store/schema.sql`, прочие файлы в `internal/store/`, `go.mod`, `go.sum` (в этой волне go.mod правит только T2 — замена драйвера на ncruces)
- **Файлы (только читает):** `internal/naming/`
- **Скилы:** `/coding-writer`

**Что сделать**
Сначала привести `go.mod`: убрать `modernc.org/sqlite` и его replace, добавить `github.com/ncruces/go-sqlite3 v0.29.0` (см. арх-решение 2). Затем реализовать `Store` по сигнатурам из «Контрактов» поверх `database/sql` + `github.com/ncruces/go-sqlite3/driver` (+ анонимный импорт `…/embed`). `Open` применяет `schema.sql` (embed) и PRAGMA (WAL, foreign_keys, busy_timeout). Сортировка версий и выбор latest — сравнением через `Masterminds/semver` в Go (не строкой в SQL). `SetLatestOverride` проверяет, что версия принадлежит приложению. Токен сессии — `crypto/rand`, 32 байта hex.

**Критерии приёмки**
- Все методы контракта реализованы; `ErrExists` возвращается при дублях (app name, app_id+version).
- `LatestVersion`: без override — максимум semver (`1.10.0` > `1.9.1` > `1.9.0-rc.1`); с override — закреплённая; `(nil,nil)` без версий.
- `GetSession` просроченной сессии → `(nil, nil)` и строка удалена.
- Повторный `Open` по существующей БД не падает (идемпотентная схема).

**Проверка**
`go test ./internal/store/...` (тесты пишет R2-test; свой минимальный smoke-тест на Open+CRUD — можно и нужно).

### T3. Файловое хранилище бинарников

- **Зависит от:** T1
- **Волна:** 2
- **Файлы (владеет):** `internal/files/files.go`, прочие файлы в `internal/files/`
- **Файлы (только читает):** `internal/naming/`, `go.mod`
- **Скилы:** `/coding-writer`

**Что сделать**
`Storage` по контракту. `Save`: валидация всех трёх имён через `internal/naming` (защита от traversal — здесь обязательна, даже если хендлер уже проверял), стрим в temp-файл `{Root}/.tmp/` через `io.TeeReader` в `sha256`, сверка с `wantSHA256` (регистронезависимо; пустая строка — не сверять), `MkdirAll(0o755)` + `os.Rename`; на любой ошибке temp удаляется. Если целевой файл уже существует — ошибка (перезапись запрещена).

**Критерии приёмки**
- Успешный `Save` кладёт файл в `{Root}/{app}/{version}/{filename}`, возвращает корректные sha256 (hex, нижний регистр) и размер.
- Неверный `wantSHA256` → `ErrHashMismatch`, в `{Root}` нет ни файла, ни temp-остатков.
- `Save` с `app="../evil"` → ошибка валидации, ФС не тронута.
- Повторный `Save` того же пути → ошибка, оригинал не перезаписан.

**Проверка**
`go test ./internal/files/...` (минимальный собственный тест + основное покрытие в R2-test).

### R2-test. Тесты волны 2

- **Зависит от:** T2, T3
- **Волна:** 2-ревью
- **Файлы (владеет):** `internal/store/*_test.go`, `internal/files/*_test.go`, `docs/plans/reviews/app-artifactory-R2-test.md` (+ `.json`)
- **Файлы (только читает):** весь код волн 1–2
- **Скилы:** `/coding-test`

**Что проверить**
Критерии приёмки T2 и T3 из этого плана, включая краевые: semver-сортировка с prerelease, override на чужую версию, гонка двух `CreateVersion` с одной версией (UNIQUE), `Save` пустого файла, большого файла (потоково, без загрузки в память целиком), несоответствие регистра hex-хеша.

**Критерий завершения**
Отчёт записан; статус PASS/FAIL; блокирующие находки перенесены в F2.

### F2. Исправления по волне 2

- **Зависит от:** R2-test
- **Волна:** 2-ревью
- **Файлы (владеет):** те же, что T2 и T3
- **Скилы:** `/coding-writer`

Закрыть блокирующие находки R2-test. Нет находок — закрывается пустой.

### T4. Аутентификация и middleware

- **Зависит от:** T2
- **Волна:** 3
- **Файлы (владеет):** `internal/auth/auth.go`, прочие файлы в `internal/auth/`
- **Файлы (только читает):** `internal/store/`, `internal/config/`
- **Скилы:** `/coding-writer`

**Что сделать**
Всё по сигнатурам контракта. bcrypt cost по умолчанию (10). `RequireBasic`: разбор `Authorization: Basic`, поиск пользователя, `CheckPassword`; сравнение имени через `subtle.ConstantTimeCompare` не требуется (bcrypt сам медленный), но при отсутствии пользователя всё равно прогонять bcrypt по фиктивному хешу (не палим существование по таймингу). `RequireSession`: кука `apprepo_session` → `store.GetSession`; нет/просрочена → 303 `/login?next={url}` (next — только относительный путь, начинающийся с `/`, иначе `/`). Пользователь кладётся в `context`.

**Критерии приёмки**
- Basic с верными кредами пропускает, кладёт пользователя в контекст; с неверными → 401 + `WWW-Authenticate`.
- Session-middleware без куки → 303 на `/login?next=…`; с валидной — пропускает.
- `LoginUser` с неверным паролем → ошибка, кука не ставится. Кука: HttpOnly, SameSite=Lax, Path=/, срок 7 суток.
- open-redirect через `next=https://evil` невозможен.

**Проверка**
`go test ./internal/auth/...` — httptest-юниты в составе задачи (тестовые файлы `internal/auth/*_test.go` принадлежат T4).

### T5. Веб-UI

- **Зависит от:** T2, T3
- **Волна:** 3
- **Файлы (владеет):** `internal/web/` целиком (хендлеры, `templates/`, embed)
- **Файлы (только читает):** `internal/store/`, `internal/files/`, `internal/auth/` (сигнатуры из контракта), `internal/naming/`, `internal/config/`
- **Скилы:** `/coding-writer`

**Что сделать**
`web.Register` по маршрутам контракта. Страницы: login (единственная без сессии), список приложений, страница приложения. Загрузка: `r.MaxBytesReader` по `cfg.MaxUploadBytes` → `multipart` → потоково в `files.Save` (без чтения файла в память), затем `store.CreateVersion`; при ошибке вставки — `files.Remove`. Ошибки (`ErrHashMismatch`, `ErrExists`, валидация) показываются на странице приложения человекочитаемо. Управление latest: select версий + `auto`. Все POST — с CSRF-защитой: кука `apprepo_csrf` + hidden input, сверка в middleware (double-submit cookie, без внешних библиотек). Шаблоны — `embed.FS`, минимальный чистый CSS без внешних CDN. На странице приложения у каждой версии — прямая ссылка `/download/{app}/{version}` и бейдж latest.

**Критерии приёмки**
- Незалогиненного с `/` редиректит на `/login`; после логина возвращает на `next`.
- Создание приложения с невалидным именем → форма с ошибкой, ничего не создано.
- Загрузка валидного файла с верным sha256 → версия в списке, файл на диске; с неверным → ошибка на странице, ничего не сохранено.
- POST без CSRF-токена → 403.
- Назначение latest вручную и возврат в auto работают со страницы.

**Проверка**
`go build ./...`; httptest на ключевые хендлеры (файлы `internal/web/*_test.go` — владение T5).

### T6. JSON API + скачивание

- **Зависит от:** T2, T3
- **Волна:** 3
- **Файлы (владеет):** `internal/api/` целиком
- **Файлы (только читает):** `internal/store/`, `internal/files/`, `internal/auth/`, `internal/naming/`, `internal/config/`
- **Скилы:** `/coding-writer`

**Что сделать**
`api.Register` по таблице маршрутов и формату объекта версии из контракта. Всё под `RequireBasic`. `download_url` строится от `cfg.BaseURL`. Скачивание: `http.ServeContent`/`ServeFile` c `Content-Disposition: attachment; filename="…"` (RFC 5987 при не-ASCII), `X-Checksum-Sha256`; поддержка Range приходит бесплатно от ServeFile — оставить. `PUT` заливка: `MaxBytesReader`, тело → `files.Save`, `X-Checksum-Sha256` как wantSHA, `?filename=` через `naming.ValidateFilename`, ~~дефолт `{name}-{version}`~~ (*изменено волной 7 (T23): дефолта нет, отсутствующий или пустой параметр → 400 `filename_required`*); откат файла при ошибке вставки в БД. Все ошибки — JSON по кодам контракта.

**Критерии приёмки**
- Без Basic Auth любой `/api/…` и `/download/…` → 401 JSON `unauthorized` (для download допустим text), с `WWW-Authenticate`.
- `GET /api/apps/{name}/latest` без версий → 404 `not_found`; с override — закреплённая.
- `PUT` с верным хешем → 201 и объект версии с `download_url`; с неверным → 422 `hash_mismatch`, файла нет; повторный `PUT` той же версии → 409.
- `GET /download/{app}/latest` отдаёт байты, идентичные загруженным (сверка sha256), с корректными заголовками.

**Проверка**
`go build ./...`; httptest на PUT/GET/download (файлы `internal/api/*_test.go` — владение T6).

### T7. Интеграция

- **Зависит от:** T4, T5, T6
- **Волна:** 4
- **Файлы (владеет):** `cmd/apprepo/main.go`, `deploy/apprepo.service`, `deploy/apprepo.env.example`, `scripts/smoke.sh`, `README.md`
- **Файлы (только читает):** все internal-пакеты
- **Скилы:** `/coding-writer`

**Что сделать**
Собрать всё в `main.go`: config → store.Open → files.Storage → auth → mux с web.Register + api.Register + `/healthz`; `http.Server` с таймаутами (ReadHeader 10s, Idle 120s; без общего Write-таймаута, чтобы не рубить большие скачивания) и graceful shutdown по SIGTERM/SIGINT. Реализовать `user add <username>`: пароль из `APPREPO_PASSWORD` или интерактивно (`golang.org/x/term`, дважды). Если в БД нет пользователей, `serve` пишет в лог подсказку про `user add`. systemd unit: `DynamicUser=no`, `User=apprepo`, `EnvironmentFile`, `Restart=on-failure`, `ReadWritePaths=/opt/apps`. `scripts/smoke.sh`: поднять сервер на временном data-dir, создать пользователя, curl-сценарий (создать приложение → PUT две версии → проверить latest → скачать и сверить sha256 → закрепить latest → проверить) с `set -e`. README — краткий: сборка, запуск, конфиг, curl-примеры (наполнит R4-qa).

**Критерии приёмки**
- `make build` собирает бинарник; `scripts/smoke.sh` проходит целиком на чистой машине.
- `apprepo user add alice` с `APPREPO_PASSWORD=…` создаёт пользователя без интерактива.
- SIGTERM во время работы завершает сервер без обрыва активных ответов (graceful).
- Unit-файл валиден (`systemd-analyze verify` при наличии; иначе ручная проверка синтаксиса).

**Проверка**
`go build ./... && go test ./... && bash scripts/smoke.sh`

### R4-test. Интеграционные тесты

- **Зависит от:** T7
- **Волна:** 4-ревью
- **Файлы (владеет):** `internal/integration/` (новые интеграционные тесты), `docs/plans/reviews/app-artifactory-R4-test.md` (+ `.json`)
- **Скилы:** `/coding-test`

**Что проверить**
Сквозные сценарии на собранном сервисе (httptest поверх полного mux из main-wiring, вынесенного в конструктор): полный happy-path из smoke, плюс краевые — загрузка через UI и API одной и той же версии (409), latest при prerelease-версиях, скачивание несуществующего, Basic Auth с несуществующим пользователем, CSRF, загрузка ровно на границе max-upload. Покрытие изменённых волнами 3–4 строк — посчитать и включить в отчёт.

### R4-sec. Секьюрити-ревью

- **Зависит от:** T7
- **Волна:** 4-ревью
- **Файлы (владеет):** `docs/plans/reviews/app-artifactory-R4-sec.md`
- **Скилы:** `/coding-secure`

**Что проверить**
Path traversal во всех местах, где имена попадают в пути ФС; полнота покрытия auth-middleware (нет ли забытых открытых маршрутов); тайминг-утечка существования пользователя; фиксация сессии, свойства куки, open redirect в `next`; CSRF; заголовки скачивания (инъекция в Content-Disposition); отсутствие секретов в логах и ошибках; зависимости на CVE (`govulncheck`); лимиты размера тела на всех входах.

### R4-qa. QA-приёмка и документация

- **Зависит от:** T7
- **Волна:** 4-ревью
- **Файлы (владеет):** `docs/plans/reviews/app-artifactory-R4-qa.md`, `README.md`, `CLAUDE.md`, `docs/api.md`
- **Скилы:** `/coding-qa`

**Что проверить/сделать**
Пройти все критерии готовности из шапки плана по собранному сервису; оценить качество кода и тестов; довести документацию: README (установка, systemd, конфиг, скриншот-описание UI, curl-примеры всех API-маршрутов), `docs/api.md` (полное описание API), `CLAUDE.md` (карта проекта для агентов). Дописывать docstring-комментарии разрешено.

### F4. Исправления по волне 4

- **Зависит от:** R4-test, R4-sec, R4-qa
- **Волна:** 4-ревью
- **Файлы (владеет):** всё, чем владели T2–T7
- **Скилы:** `/coding-writer`

Закрыть блокирующие находки. После — перепрогон затронутых проверяющих в отчёты `…-round2.md`.

## Общая верификация

```bash
go build ./... && go vet ./... && go test ./... && bash scripts/smoke.sh
```

Плюс ручной прогон UI-сценария из критериев готовности.

## Риски и открытые вопросы

- **Большие файлы:** всё потоковое (multipart → temp, PUT → temp, отдача через ServeFile); проверить в R4-test, что память не растёт с размером файла.
- **`/opt/apps` в тестах недоступен:** все тесты и smoke используют временные каталоги; дефолт `/opt/apps` — только прод.
- **Basic Auth без TLS небезопасен:** фиксируем в README требование reverse-proxy с TLS. Не чиним в коде.
- **Точки остановки для командира:** создание удалённого репозитория; мерж в `main`; публикация чего-либо наружу.
