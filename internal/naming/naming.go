// Package naming validates app names, versions and filenames before they
// touch the filesystem or database. It is the single path-traversal guard:
// every external input must pass through it.
package naming

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/Masterminds/semver/v3"
)

var appNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// userNameRe deliberately repeats the app-name alphabet: ASCII letters and
// digits plus `._-`, first character alphanumeric, at most 64 bytes.
//
// Почему только ASCII, а не «любые буквы Unicode»:
//   - имя уходит в HTTP Basic, а RFC 7617 не задаёт кодировку для `user:pass`
//     совместимым образом — разные клиенты шлют её то в latin-1, то в UTF-8,
//     и учётка с не-ASCII именем аутентифицируется не отовсюду. Ровно та же
//     болезнь, что и у двоеточия, только тише;
//   - гомоглифы: кириллические `а`, `о`, `е` неотличимы от латинских на глаз,
//     то есть ровно та пара визуально одинаковых учёток, ради которой имя
//     вообще нормализуется. Юникод-нормализация тут не спасает: NFC разные
//     алфавиты не сводит;
//   - имя ходит в пути URL (`/api/users/{username}`) и в строках журнала.
var userNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// MaxPasswordBytes is the bcrypt input limit: a longer password is refused by
// the hasher outright (not silently truncated), so it must be caught as a
// client error rather than surface as a 500.
const MaxPasswordBytes = 72

// MinPasswordBytes is the only password strength requirement there is.
//
// Восемь байт — не «надёжный пароль», а нижняя граница, ниже которой bcrypt
// перестаёт быть препятствием: ограничения частоты входа в сервисе нет
// (R4-S7 открыто), поэтому единственная цена перебора — стоимость хеша.
// Словарей, классов символов и проверки на совпадение с именем нарочно нет:
// каждая такая проверка гонит пользователя в «Password1!» и требует списков,
// которые надо обновлять. Длина же — единственное требование, которое ничего
// не стоит и не устаревает (R6-sec, S3-а).
const MinPasswordBytes = 8

// NormalizeUsername trims surrounding whitespace and validates what is left,
// returning the canonical form to store and to look up by. It is the single
// gate for account names on every path — API, UI and CLI, creation and lookup
// alike: a name normalised in one interface and taken verbatim in another
// produces two visually identical accounts, and a block lands only on one.
//
// Двоеточие запрещено отдельно от прочего: HTTP Basic кодирует `user:password`,
// поэтому учётка с двоеточием в имени не может войти никогда — 201 на такое
// имя выдаёт мёртвую с рождения учётку (для роли `deployer`, у которой нет
// другого входа, кроме API, — безвозвратно).
func NormalizeUsername(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("username must not be empty")
	}
	if !userNameRe.MatchString(name) {
		return "", fmt.Errorf("invalid username %q: must match %s", name, userNameRe)
	}
	return name, nil
}

// LegacyUsername reports whether an account name stored in the database is no
// longer addressable by itself. Критерий — не «имя невалидно», а «имя не
// совпадает со своей нормальной формой»: учётка ищется по нормализованной
// строке, поэтому и отвергаемое имя ("аlice"), и то, что нормализуется в чужое
// ("admin " → "admin", операция молча уходит не на ту строку), одинаково
// недостижимы по своему имени из API и CLI.
//
// Живёт здесь, а не рядом с вызывающими: предупреждение в CLI и пометка на
// странице /users обязаны отбирать одни и те же учётки (R6-sec круг 3, N2).
func LegacyUsername(name string) bool {
	norm, err := NormalizeUsername(name)
	return err != nil || norm != name
}

// BrokenBasicUsername reports whether a stored name cannot authenticate over
// HTTP Basic at all. Двоеточие — не такое же неудобство, как пробел или
// не-ASCII: Basic кодирует пару `user:password`, поэтому сервер читает именем
// всё до первого двоеточия и такая учётка получает 401 всегда, а с ролью
// `deployer` (без входа в UI) она мертва полностью. Живёт рядом с
// LegacyUsername: предупреждение CLI и пометка на /users обязаны разделять
// случаи одинаково (R6-qa круг 2).
func BrokenBasicUsername(name string) bool { return strings.Contains(name, ":") }

// ValidatePassword checks a new password before it reaches bcrypt.
func ValidatePassword(pw string) error {
	switch {
	case pw == "":
		return errors.New("password must not be empty")
	case len(pw) < MinPasswordBytes:
		return fmt.Errorf("password must be at least %d bytes, got %d", MinPasswordBytes, len(pw))
	case len(pw) > MaxPasswordBytes:
		return fmt.Errorf("password must be at most %d bytes, got %d", MaxPasswordBytes, len(pw))
	}
	return nil
}

// ValidateAppName accepts ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$ and rejects the
// reserved name "latest".
func ValidateAppName(name string) error {
	if name == "latest" {
		return errors.New(`app name "latest" is reserved`)
	}
	if !appNameRe.MatchString(name) {
		return fmt.Errorf("invalid app name %q: must match %s", name, appNameRe)
	}
	return nil
}

// ValidateVersion accepts a strict semver version, with an optional "v"
// prefix, and returns its canonical form without the prefix.
func ValidateVersion(v string) (canonical string, err error) {
	ver, err := semver.StrictNewVersion(strings.TrimPrefix(v, "v"))
	if err != nil {
		return "", fmt.Errorf("invalid version %q: %w", v, err)
	}
	return ver.String(), nil
}

// ValidateFilename accepts a plain non-blank basename of at most 255 bytes:
// no control characters, no path separators, not "." or "..".
func ValidateFilename(name string) error {
	switch {
	case name == "":
		return errors.New("filename is empty")
	// Имя из одних пробелов — то же «пусто», записанное иначе: на диске такой
	// файл неотличим глазами, а браузер сохранит скачанное под своим запасным
	// именем. Обрезаются только края, поэтому пробелы ВНУТРИ имени
	// ("app v1.tar.gz") остаются законными, и уже залитые версии не меняются.
	case strings.TrimSpace(name) == "":
		return fmt.Errorf("filename %q is blank", name)
	// Управляющие символы отвергаются целиком категорией Cc (C0, DEL, C1), а не
	// перечислением: NUL ядро не принимает вовсе и os.Link падает на нём
	// «invalid argument» — то есть без этой проверки клиентский ввод приезжает
	// 500-й ошибкой уже после того, как тело выкачано целиком (R7-qa, находка 1).
	// Остальные Cc — не «на всякий случай»: перевод строки в имени уезжает в
	// Content-Disposition и в строки журнала, а имя с \b или \r в терминале
	// оператора выглядит не тем, что лежит на диске. Законного имени файла с
	// управляющим символом внутри не бывает, поэтому граница проходит по всей
	// категории — одно предикатное слово вместо списка исключений.
	// Проверка работает на входе: уже залитые версии со старыми именами не
	// перепроверяются и продолжают скачиваться (см. /download).
	case strings.IndexFunc(name, unicode.IsControl) >= 0:
		return fmt.Errorf("filename %q must not contain control characters", name)
	case len(name) > 255:
		return fmt.Errorf("filename longer than 255 bytes")
	case strings.ContainsAny(name, `/\`):
		return fmt.Errorf("filename %q must not contain path separators", name)
	// Without separators ".." cannot traverse, but "." and ".." are not files.
	case name == "." || name == "..":
		return fmt.Errorf("filename %q is not allowed", name)
	}
	return nil
}
