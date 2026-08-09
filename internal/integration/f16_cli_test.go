package integration

// F16 (R6-qa круг 2): CLI ищет учётку по нормализованному имени, значит и в
// отказе обязан называть его. Иначе `user role "admin " developer` отвечает
// `user "admin " not found` — оператор, разбирающий старые имена, читает это
// как «строки нет вовсе», хотя в `user list` она видна.

import (
	"strings"
	"testing"
)

func TestCLIUserNotFoundPrintsNormalizedName(t *testing.T) {
	if testing.Short() {
		t.Skip("сборка бинарника — пропускаем в -short")
	}
	root := t.TempDir()
	cfg := cfgAt(root, defaultMaxUpload)
	run := cliRunner(t, cfg.DataDir)

	if out, code := run([]string{"APPREPO_PASSWORD=root-pass"}, "user", "add", "root"); code != 0 {
		t.Fatalf("user add root: exit = %d; out: %s", code, out)
	}

	out, code := run(nil, "user", "role", "ghost ", "developer")
	if code != 1 {
		t.Fatalf("exit = %d, want 1; out: %s", code, out)
	}
	if !strings.Contains(out, `user "ghost" not found`) {
		t.Errorf("сообщение не называет нормализованное имя: %s", out)
	}
	// Существующая учётка по «грязному» имени находится — сообщение об отказе
	// не должно противоречить этому.
	if out, code := run([]string{"APPREPO_PASSWORD=ops-password"},
		"user", "add", "ops", "-role", "developer"); code != 0 {
		t.Fatalf("user add ops: exit = %d; out: %s", code, out)
	}
	if out, code := run(nil, "user", "role", " ops ", "maintainer"); code != 0 {
		t.Fatalf("user role \" ops \": exit = %d; out: %s", code, out)
	}
}
