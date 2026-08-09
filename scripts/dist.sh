#!/usr/bin/env bash
# Релизные сборки под все поддерживаемые платформы: dist/<архив> + SHA256SUMS.
#
# Кросс-компиляция работает простым GOOS/GOARCH: CGO нигде не нужен (SQLite —
# чистый Go поверх wazero). Версия и коммит зашиваются через -ldflags -X;
# переопределяются переменными окружения VERSION и COMMIT.
set -euo pipefail

cd "$(dirname "$0")/.."

version="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
commit="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo none)}"
out="${DIST_DIR:-dist}"

targets="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64"

# Что кладём в архив рядом с бинарником. LICENSE появится позже — берём, если есть.
extra=(README.md)
[ -f LICENSE ] && extra+=(LICENSE)

if ! command -v zip >/dev/null; then
	echo "dist: нужен zip для windows-архива" >&2
	exit 1
fi

rm -rf "$out"
mkdir -p "$out"

for t in $targets; do
	os="${t%/*}"
	arch="${t#*/}"
	name="apprepo_${version}_${os}_${arch}"
	bin=apprepo
	[ "$os" = windows ] && bin=apprepo.exe

	mkdir -p "$out/$name"
	# -trimpath убирает пути сборочной машины, -s -w — таблицы символов и DWARF.
	CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build \
		-trimpath \
		-ldflags "-s -w -X main.version=$version -X main.commit=$commit" \
		-o "$out/$name/$bin" ./cmd/apprepo
	cp "${extra[@]}" "$out/$name/"
	# В репозитории файлы лежат с 0600; в архиве для чужой машины это мусор.
	chmod 0644 "$out/$name"/*.md "$out/$name"/LICENSE 2>/dev/null || true

	if [ "$os" = windows ]; then
		(cd "$out" && zip -qr "$name.zip" "$name")
	else
		tar -czf "$out/$name.tar.gz" -C "$out" "$name"
	fi
	rm -rf "$out/$name"
	echo "$out/$name"
done

# sha256sum есть в GNU coreutils, shasum — на macOS и в перловых системах.
sha=(sha256sum)
command -v sha256sum >/dev/null || sha=(shasum -a 256)
(cd "$out" && "${sha[@]}" apprepo_*.tar.gz apprepo_*.zip >SHA256SUMS)

ls -lh "$out"
