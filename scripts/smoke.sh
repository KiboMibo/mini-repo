#!/usr/bin/env bash
# Сквозной smoke-тест apprepo: сборка, создание пользователя, API-сценарий
# через curl. Работает целиком во временном каталоге, /opt/apps не трогает.
set -euo pipefail

cd "$(dirname "$0")/.."

TMPDIR_SMOKE="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
  [ -n "$SERVER_PID" ] && wait "$SERVER_PID" 2>/dev/null || true
  rm -rf "$TMPDIR_SMOKE"
}
trap cleanup EXIT

BIN="$TMPDIR_SMOKE/apprepo"
DATA="$TMPDIR_SMOKE/data"

# Свободный порт
PORT=18080
while (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; do exec 3>&- || true; PORT=$((PORT + 1)); done
BASE="http://127.0.0.1:$PORT"
CRED="alice:s3cret-pass"
# По учётке на роль — заводятся через CLI, проверяются через HTTP.
DEP_CRED="ci:deployer-pw"
DEV_CRED="dev:developer-pw"
MNT_CRED="mnt:maintainer-pw"

echo "== build"
go build -o "$BIN" ./cmd/apprepo

echo "== user add"
APPREPO_PASSWORD=s3cret-pass "$BIN" user add alice -data-dir "$DATA"

echo "== user add: one account per role"
APPREPO_PASSWORD="${DEP_CRED#*:}" "$BIN" user add ci  -role deployer   -data-dir "$DATA"
APPREPO_PASSWORD="${DEV_CRED#*:}" "$BIN" user add dev -role developer  -data-dir "$DATA"
APPREPO_PASSWORD="${MNT_CRED#*:}" "$BIN" user add mnt -role maintainer -data-dir "$DATA"

echo "== serve"
"$BIN" serve -addr "127.0.0.1:$PORT" -data-dir "$DATA" -base-url "$BASE" &
SERVER_PID=$!
for i in $(seq 1 50); do
  curl -fsS "$BASE/healthz" >/dev/null 2>&1 && break
  [ "$i" = 50 ] && { echo "server did not start"; exit 1; }
  sleep 0.1
done

echo "== unauthorized is rejected"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/apps")
[ "$code" = 401 ] || { echo "expected 401, got $code"; exit 1; }

echo "== create app"
curl -fsS -u "$CRED" -X POST "$BASE/api/apps" \
  -H 'Content-Type: application/json' -d '{"name":"myapp","description":"smoke"}' >/dev/null

echo "== upload two versions"
printf 'binary-one' >"$TMPDIR_SMOKE/f1"
printf 'binary-two-bigger' >"$TMPDIR_SMOKE/f2"
sha1=$(sha256sum "$TMPDIR_SMOKE/f1" | cut -d' ' -f1)
sha2=$(sha256sum "$TMPDIR_SMOKE/f2" | cut -d' ' -f1)
# ?filename= обязателен: имя приходит от клиента и приезжает обратно в
# Content-Disposition. Архивное имя с двойным расширением — ровно тот случай,
# ради которого дефолт убрали.
# ?platform=any — потому что тела здесь текстовые заглушки: определять по ним
# нечего, а «any» и значит «файл не зависит от ОС и архитектуры». Настоящий
# бинарник и настоящий архив проверяются ниже, в разделе «platform».
curl -fsS -u "$CRED" -X PUT "$BASE/api/apps/myapp/versions/1.0.0?filename=myapp-1.0.0&platform=any" \
  -H "X-Checksum-Sha256: $sha1" --data-binary @"$TMPDIR_SMOKE/f1" >/dev/null
curl -fsS -u "$CRED" -X PUT "$BASE/api/apps/myapp/versions/1.2.0?filename=myapp-1.2.0.tar.gz&platform=any" \
  --data-binary @"$TMPDIR_SMOKE/f2" >/dev/null

echo "== upload without ?filename= is refused with a self-explaining 400"
resp=$(curl -s -u "$CRED" -w '\n%{http_code}' -X PUT \
  "$BASE/api/apps/myapp/versions/4.0.0" --data-binary @"$TMPDIR_SMOKE/f1")
code=${resp##*$'\n'}
[ "$code" = 400 ] || { echo "missing filename: expected 400, got $code"; exit 1; }
echo "$resp" | grep -q '"error":"filename_required"' \
  || { echo "missing filename: expected filename_required, got: $resp"; exit 1; }
echo "$resp" | grep -q 'required and must not be empty' \
  || { echo "the refusal does not explain itself: $resp"; exit 1; }
echo "$resp" | grep -q 'filename=myapp-4.0.0.tar.gz' \
  || { echo "the refusal shows no working example: $resp"; exit 1; }
[ ! -e "$DATA/myapp/4.0.0" ] || { echo "4.0.0 must not exist on disk"; exit 1; }
# Пустое и пробельное значение — тот же отказ, что и отсутствующий параметр:
# `?filename=$ARTIFACT` с незаданной переменной в CI даёт именно пробелы.
for q in '' '%20' '%20%20%20' '%09'; do
  code=$(curl -s -u "$CRED" -o /dev/null -w '%{http_code}' -X PUT \
    "$BASE/api/apps/myapp/versions/4.0.0?filename=$q" --data-binary @"$TMPDIR_SMOKE/f1")
  [ "$code" = 400 ] || { echo "blank filename [$q]: expected 400, got $code"; exit 1; }
  [ ! -e "$DATA/myapp/4.0.0" ] || { echo "blank filename [$q]: 4.0.0 must not exist"; exit 1; }
done

echo "== wrong client hash is rejected, file not stored"
code=$(curl -s -u "$CRED" -o /dev/null -w '%{http_code}' -X PUT \
  "$BASE/api/apps/myapp/versions/2.0.0?filename=myapp-2.0.0" \
  -H "X-Checksum-Sha256: $(printf 'a%.0s' $(seq 64))" --data-binary @"$TMPDIR_SMOKE/f1")
[ "$code" = 422 ] || { echo "expected 422, got $code"; exit 1; }
[ ! -e "$DATA/myapp/2.0.0" ] || { echo "2.0.0 must not exist on disk"; exit 1; }

echo "== latest is max semver"
latest=$(curl -fsS -u "$CRED" "$BASE/api/apps/myapp/latest" | grep -o '"version":"[^"]*"' | head -1)
[ "$latest" = '"version":"1.2.0"' ] || { echo "expected latest 1.2.0, got $latest"; exit 1; }

echo "== download latest and verify sha256"
curl -fsS -u "$CRED" -D "$TMPDIR_SMOKE/hdr" -o "$TMPDIR_SMOKE/dl" "$BASE/download/myapp/latest"
got=$(sha256sum "$TMPDIR_SMOKE/dl" | cut -d' ' -f1)
[ "$got" = "$sha2" ] || { echo "downloaded sha mismatch"; exit 1; }
grep -qi "x-checksum-sha256: $sha2" "$TMPDIR_SMOKE/hdr" || { echo "missing X-Checksum-Sha256"; exit 1; }
grep -qi 'content-disposition: attachment.*myapp-1.2.0.tar.gz' "$TMPDIR_SMOKE/hdr" \
  || { echo "Content-Disposition lost the uploaded file name"; exit 1; }

echo "== multi-file archive: upload, download, unpack, compare"
# Главный сценарий волны 7: релиз из нескольких файлов уезжает архивом и обязан
# вернуться байт в байт. Отдельное приложение, чтобы не двигать latest у myapp,
# на котором держатся проверки ниже.
REL="$TMPDIR_SMOKE/release"
mkdir -p "$REL/bin/tools" "$REL/etc" "$REL/share/doc"
printf '#!/bin/sh\nexec /usr/libexec/myapp "$@"\n' >"$REL/bin/run.sh"
chmod +x "$REL/bin/run.sh"
# Не-текстовое содержимое: круг-трип должен переживать и его.
head -c 65536 /dev/urandom >"$REL/bin/tools/data.bin"
printf 'listen: :8080\nlog_level: info\n' >"$REL/etc/app.conf"
printf '# myapp\n\nMulti-file release.\n' >"$REL/share/doc/README.txt"
ARCHIVE="$TMPDIR_SMOKE/myapp-3.1.0.tar.gz"
tar -czf "$ARCHIVE" -C "$REL" .
sha_arch=$(sha256sum "$ARCHIVE" | cut -d' ' -f1)

curl -fsS -u "$CRED" -X POST "$BASE/api/apps" \
  -H 'Content-Type: application/json' -d '{"name":"archived"}' >/dev/null
code=$(curl -s -u "$CRED" -o /dev/null -w '%{http_code}' -X PUT \
  "$BASE/api/apps/archived/versions/3.1.0?filename=myapp-3.1.0.tar.gz&platform=any" \
  -H "X-Checksum-Sha256: $sha_arch" --data-binary @"$ARCHIVE")
[ "$code" = 201 ] || { echo "archive upload: expected 201, got $code"; exit 1; }

curl -fsS -u "$CRED" -D "$TMPDIR_SMOKE/arch-hdr" -o "$TMPDIR_SMOKE/arch-dl" \
  "$BASE/download/archived/3.1.0"
got=$(sha256sum "$TMPDIR_SMOKE/arch-dl" | cut -d' ' -f1)
[ "$got" = "$sha_arch" ] || { echo "archive round-trip: sha mismatch"; exit 1; }
# Имя с расширением — то, ради чего ?filename= сделан обязательным: без него
# архив скачивался бы файлом, который нечем открыть.
grep -qi 'content-disposition: attachment.*filename=.*myapp-3.1.0\.tar\.gz' "$TMPDIR_SMOKE/arch-hdr" \
  || { echo "archive lost its name/extension in Content-Disposition"; exit 1; }

# Распаковка и пофайловая сверка: архив должен не просто совпасть по sha, а
# развернуться в тот же набор вложенных путей с тем же содержимым.
UNPACK="$TMPDIR_SMOKE/unpack"
mkdir -p "$UNPACK"
tar -xzf "$TMPDIR_SMOKE/arch-dl" -C "$UNPACK"
for f in bin/run.sh bin/tools/data.bin etc/app.conf share/doc/README.txt; do
  [ -f "$UNPACK/$f" ] || { echo "unpacked archive has no $f"; exit 1; }
done
diff -r "$REL" "$UNPACK" >/dev/null || { echo "unpacked archive differs from the original"; exit 1; }
[ -x "$UNPACK/bin/run.sh" ] || { echo "executable bit lost in the round trip"; exit 1; }

echo "== platform: detected on a real binary, demanded from an archive"
# Голый бинарник опознаётся сам — ради этого автоопределение и делалось, чтобы
# существующие CI-скрипты не правились ни одной строкой. Подопытный под рукой:
# это сам собранный apprepo.
HOST_PLATFORM="$(go env GOOS)/$(go env GOARCH)"
curl -fsS -u "$CRED" -o "$TMPDIR_SMOKE/plat.json" -X PUT \
  "$BASE/api/apps/archived/versions/3.2.0?filename=apprepo-3.2.0" --data-binary @"$BIN"
grep -q "\"platform\":\"$HOST_PLATFORM\"" "$TMPDIR_SMOKE/plat.json" \
  || { echo "platform of a bare binary not detected, want $HOST_PLATFORM: $(cat "$TMPDIR_SMOKE/plat.json")"; exit 1; }

# У архива читать нечего: без ?platform= это 400 с самодостаточным текстом (как
# у filename_required — его читает сломавшийся пайплайн), и ничего не сохранено.
resp=$(curl -s -u "$CRED" -w '\n%{http_code}' -X PUT \
  "$BASE/api/apps/archived/versions/3.3.0?filename=myapp-3.3.0.tar.gz" --data-binary @"$ARCHIVE")
code=${resp##*$'\n'}
[ "$code" = 400 ] || { echo "archive without platform: expected 400, got $code"; exit 1; }
echo "$resp" | grep -q '"error":"platform_required"' \
  || { echo "archive without platform: expected platform_required, got: $resp"; exit 1; }
echo "$resp" | grep -q 'platform=linux/amd64' \
  || { echo "the refusal shows no working example: $resp"; exit 1; }
[ ! -e "$DATA/archived/3.3.0" ] || { echo "3.3.0 must not exist on disk"; exit 1; }

# Тот же архив с явной платформой проходит.
code=$(curl -s -u "$CRED" -o /dev/null -w '%{http_code}' -X PUT \
  "$BASE/api/apps/archived/versions/3.3.0?filename=myapp-3.3.0.tar.gz&platform=any" \
  --data-binary @"$ARCHIVE")
[ "$code" = 201 ] || { echo "archive with ?platform=any: expected 201, got $code"; exit 1; }

# --- разграничение прав: по одному запрету и одному разрешению на роль ---

echo "== deployer: cannot upload a version, but downloads"
code=$(curl -s -u "$DEP_CRED" -o /dev/null -w '%{http_code}' -X PUT \
  "$BASE/api/apps/myapp/versions/3.0.0?filename=myapp-3.0.0" --data-binary @"$TMPDIR_SMOKE/f1")
[ "$code" = 403 ] || { echo "deployer upload: expected 403, got $code"; exit 1; }
[ ! -e "$DATA/myapp/3.0.0" ] || { echo "3.0.0 must not exist on disk"; exit 1; }
code=$(curl -s -u "$DEP_CRED" -o /dev/null -w '%{http_code}' "$BASE/download/myapp/1.2.0")
[ "$code" = 200 ] || { echo "deployer download: expected 200, got $code"; exit 1; }

echo "== deployer: signs in but the UI stays closed (no PermUI)"
JAR="$TMPDIR_SMOKE/jar"
curl -fsS -c "$JAR" -D "$TMPDIR_SMOKE/login-hdr" -o /dev/null "$BASE/login"
CSRF=$(sed -n 's/.*apprepo_csrf=\([^;]*\).*/\1/p' "$TMPDIR_SMOKE/login-hdr")
[ -n "$CSRF" ] || { echo "no CSRF cookie on /login"; exit 1; }
code=$(curl -s -b "apprepo_csrf=$CSRF" -c "$JAR" -o /dev/null -w '%{http_code}' -X POST "$BASE/login" \
  --data-urlencode "csrf_token=$CSRF" \
  --data-urlencode "username=${DEP_CRED%%:*}" --data-urlencode "password=${DEP_CRED#*:}")
[ "$code" = 303 ] || { echo "deployer login: expected 303, got $code"; exit 1; }
code=$(curl -s -b "$JAR" -o /dev/null -w '%{http_code}' "$BASE/")
[ "$code" = 403 ] || { echo "deployer in UI: expected 403, got $code"; exit 1; }

echo "== developer: cannot create an app, but uploads a version"
code=$(curl -s -u "$DEV_CRED" -o /dev/null -w '%{http_code}' -X POST "$BASE/api/apps" \
  -H 'Content-Type: application/json' -d '{"name":"by-developer"}')
[ "$code" = 403 ] || { echo "developer create app: expected 403, got $code"; exit 1; }
code=$(curl -s -u "$DEV_CRED" -o /dev/null -w '%{http_code}' -X PUT \
  "$BASE/api/apps/myapp/versions/1.1.0?filename=myapp-1.1.0&platform=any" --data-binary @"$TMPDIR_SMOKE/f1")
[ "$code" = 201 ] || { echo "developer upload: expected 201, got $code"; exit 1; }

echo "== maintainer: creates an app, but cannot manage users"
curl -fsS -u "$MNT_CRED" -X POST "$BASE/api/apps" \
  -H 'Content-Type: application/json' -d '{"name":"by-maintainer"}' >/dev/null
code=$(curl -s -u "$MNT_CRED" -o /dev/null -w '%{http_code}' "$BASE/api/users")
[ "$code" = 403 ] || { echo "maintainer user list: expected 403, got $code"; exit 1; }

echo "== admin: manages accounts"
curl -fsS -u "$CRED" -X POST "$BASE/api/users" \
  -H 'Content-Type: application/json' \
  -d '{"username":"smoke-bot","password":"bot-password","role":"deployer"}' >/dev/null
curl -fsS -u "$CRED" "$BASE/api/users" | grep -q '"username":"smoke-bot"' \
  || { echo "smoke-bot is missing from the user list"; exit 1; }
code=$(curl -s -u "$CRED" -o /dev/null -w '%{http_code}' -X DELETE "$BASE/api/users/smoke-bot")
[ "$code" = 204 ] || { echo "delete user: expected 204, got $code"; exit 1; }

echo "== a short password is refused by all three interfaces"
code=$(curl -s -u "$CRED" -o /dev/null -w '%{http_code}' -X POST "$BASE/api/users" \
  -H 'Content-Type: application/json' \
  -d '{"username":"weak","password":"short","role":"deployer"}')
[ "$code" = 400 ] || { echo "short password over the API: expected 400, got $code"; exit 1; }
if curl -fsS -u "$CRED" "$BASE/api/users" | grep -q '"username":"weak"'; then
  echo "account created with a short password"; exit 1
fi
# UI: та же форма, что у админа в браузере, отвечает 400 с текстом на странице.
# Своя сессия: $JAR выше принадлежит deployer'у, которого в интерфейс не пускают.
AJAR="$TMPDIR_SMOKE/admin-jar"
curl -fsS -c "$AJAR" -D "$TMPDIR_SMOKE/admin-hdr" -o /dev/null "$BASE/login"
ACSRF=$(sed -n 's/.*apprepo_csrf=\([^;]*\).*/\1/p' "$TMPDIR_SMOKE/admin-hdr")
code=$(curl -s -b "$AJAR" -c "$AJAR" -o /dev/null -w '%{http_code}' -X POST "$BASE/login" \
  --data-urlencode "csrf_token=$ACSRF" \
  --data-urlencode "username=${CRED%%:*}" --data-urlencode "password=${CRED#*:}")
[ "$code" = 303 ] || { echo "admin login: expected 303, got $code"; exit 1; }
code=$(curl -s -b "$AJAR" -c "$AJAR" -o "$TMPDIR_SMOKE/weak.html" -w '%{http_code}' \
  -X POST "$BASE/users" --data-urlencode "csrf_token=$ACSRF" \
  --data-urlencode "username=weak-ui" --data-urlencode "password=short" \
  --data-urlencode "role=deployer")
[ "$code" = 400 ] || { echo "short password in the UI: expected 400, got $code"; exit 1; }
grep -q 'at least 8 bytes' "$TMPDIR_SMOKE/weak.html" \
  || { echo "the UI form does not explain the password policy"; exit 1; }
# CLI: exit 1 и внятный текст, учётка не заводится.
if APPREPO_PASSWORD=short "$BIN" user add weak-cli -role deployer -data-dir "$DATA" \
     >"$TMPDIR_SMOKE/weak.out" 2>&1; then
  echo "CLI created an account with a short password"; exit 1
fi
grep -q 'at least 8 bytes' "$TMPDIR_SMOKE/weak.out" \
  || { echo "CLI does not explain the password policy: $(cat "$TMPDIR_SMOKE/weak.out")"; exit 1; }

echo "== the last admin cannot be demoted"
code=$(curl -s -u "$CRED" -o /dev/null -w '%{http_code}' -X PATCH "$BASE/api/users/alice" \
  -H 'Content-Type: application/json' -d '{"role":"developer"}')
[ "$code" = 409 ] || { echo "demote last admin: expected 409, got $code"; exit 1; }
if ! "$BIN" user role alice developer -data-dir "$DATA" >/dev/null 2>&1; then :; else
  echo "CLI demoted the last admin"; exit 1
fi
curl -fsS -u "$CRED" "$BASE/api/me" | grep -q '"role":"admin"' \
  || { echo "alice lost the admin role"; exit 1; }

echo "== JSON API accepts only application/json bodies"
# Весь класс Content-Type, с которым кросс-сайтовый запрос уходит из браузера
# без preflight (значит, доступен атакующему), плюс неразбираемый мусор: рубеж
# обязан падать закрыто и на нём. 'none' — заголовка нет вовсе; curl убирает
# свой умолчательный заголовок, если после имени пусто (-H 'Content-Type:').
for ct in 'none' 'text/plain' 'multipart/form-data; boundary=x' \
          'application/x-www-form-urlencoded' 'garbage' '/' 'text/plain;;;'; do
  if [ "$ct" = none ]; then hdr='Content-Type:'; else hdr="Content-Type: $ct"; fi
  code=$(curl -s -u "$CRED" -o /dev/null -w '%{http_code}' -X POST "$BASE/api/users" \
    -H "$hdr" --data-binary '{"username":"evil","password":"pw1234567","role":"admin"}')
  [ "$code" = 415 ] || { echo "create user [$ct]: expected 415, got $code"; exit 1; }
  code=$(curl -s -u "$CRED" -o /dev/null -w '%{http_code}' -X POST "$BASE/api/users/alice/password" \
    -H "$hdr" --data-binary '{"password":"hijacked1"}')
  [ "$code" = 415 ] || { echo "reset password [$ct]: expected 415, got $code"; exit 1; }
done
if curl -fsS -u "$CRED" "$BASE/api/users" | grep -q '"username":"evil"'; then
  echo "account created by a cross-site body"; exit 1
fi
# Пароль админа не заменён — иначе $CRED уже не пускал бы.
curl -fsS -u "$CRED" "$BASE/api/me" >/dev/null || { echo "admin password was replaced"; exit 1; }
# Разрешённое работает: charset допустим, пустому телу заголовок не нужен.
code=$(curl -s -u "$CRED" -o /dev/null -w '%{http_code}' -X PATCH "$BASE/api/users/alice" \
  -H 'Content-Type: application/json; charset=utf-8' -d '{}')
[ "$code" = 200 ] || { echo "application/json; charset=utf-8: expected 200, got $code"; exit 1; }
code=$(curl -s -u "$CRED" -o /dev/null -w '%{http_code}' -X PATCH "$BASE/api/users/alice" -H 'Content-Type:')
[ "$code" = 200 ] || { echo "empty PATCH body: expected 200, got $code"; exit 1; }

echo "== version uploaded by developer is gone before the latest checks"
code=$(curl -s -u "$CRED" -o /dev/null -w '%{http_code}' -X DELETE "$BASE/api/apps/myapp/versions/1.1.0")
[ "$code" = 204 ] || { echo "expected 204 on delete 1.1.0, got $code"; exit 1; }

echo "== pin latest to 1.0.0 and verify"
curl -fsS -u "$CRED" -X POST "$BASE/api/apps/myapp/latest" \
  -H 'Content-Type: application/json' -d '{"version":"1.0.0"}' >/dev/null
latest=$(curl -fsS -u "$CRED" "$BASE/api/apps/myapp/latest" | grep -o '"version":"[^"]*"' | head -1)
[ "$latest" = '"version":"1.0.0"' ] || { echo "expected pinned 1.0.0, got $latest"; exit 1; }
curl -fsS -u "$CRED" -o "$TMPDIR_SMOKE/dl1" "$BASE/download/myapp/latest"
got=$(sha256sum "$TMPDIR_SMOKE/dl1" | cut -d' ' -f1)
[ "$got" = "$sha1" ] || { echo "pinned download sha mismatch"; exit 1; }

echo "== unpin (auto) restores 1.2.0"
curl -fsS -u "$CRED" -X POST "$BASE/api/apps/myapp/latest" \
  -H 'Content-Type: application/json' -d '{"version":"auto"}' >/dev/null
latest=$(curl -fsS -u "$CRED" "$BASE/api/apps/myapp/latest" | grep -o '"version":"[^"]*"' | head -1)
[ "$latest" = '"version":"1.2.0"' ] || { echo "expected auto 1.2.0, got $latest"; exit 1; }

echo "== rename app: new name serves, old name is gone"
curl -fsS -u "$CRED" -X PATCH "$BASE/api/apps/myapp" \
  -H 'Content-Type: application/json' -d '{"name":"renamed"}' >/dev/null
curl -fsS -u "$CRED" -o "$TMPDIR_SMOKE/dl2" "$BASE/download/renamed/1.2.0"
got=$(sha256sum "$TMPDIR_SMOKE/dl2" | cut -d' ' -f1)
[ "$got" = "$sha2" ] || { echo "download after rename: sha mismatch"; exit 1; }
code=$(curl -s -u "$CRED" -o /dev/null -w '%{http_code}' "$BASE/download/myapp/1.2.0")
[ "$code" = 404 ] || { echo "old name must be 404 after rename, got $code"; exit 1; }
[ -d "$DATA/renamed" ] || { echo "$DATA/renamed must exist after rename"; exit 1; }
[ ! -d "$DATA/myapp" ] || { echo "$DATA/myapp must be gone after rename"; exit 1; }

echo "== delete version: latest recomputed, files gone"
code=$(curl -s -u "$CRED" -o /dev/null -w '%{http_code}' -X DELETE "$BASE/api/apps/renamed/versions/1.2.0")
[ "$code" = 204 ] || { echo "expected 204 on delete version, got $code"; exit 1; }
[ ! -d "$DATA/renamed/1.2.0" ] || { echo "version dir must be gone from disk"; exit 1; }
latest=$(curl -fsS -u "$CRED" "$BASE/api/apps/renamed/latest" | grep -o '"version":"[^"]*"' | head -1)
[ "$latest" = '"version":"1.0.0"' ] || { echo "expected latest 1.0.0 after delete, got $latest"; exit 1; }
code=$(curl -s -u "$CRED" -o /dev/null -w '%{http_code}' "$BASE/download/renamed/1.2.0")
[ "$code" = 404 ] || { echo "deleted version must be 404, got $code"; exit 1; }

echo "== delete app: row and directory disappear"
code=$(curl -s -u "$CRED" -o /dev/null -w '%{http_code}' -X DELETE "$BASE/api/apps/renamed")
[ "$code" = 204 ] || { echo "expected 204 on delete app, got $code"; exit 1; }
test ! -d "$DATA/renamed" || { echo "$DATA/renamed must be gone from disk"; exit 1; }
code=$(curl -s -u "$CRED" -o /dev/null -w '%{http_code}' "$BASE/api/apps/renamed")
[ "$code" = 404 ] || { echo "deleted app must be 404, got $code"; exit 1; }

echo "== graceful shutdown"
kill -TERM "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

echo "SMOKE OK"
