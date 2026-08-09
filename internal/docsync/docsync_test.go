// Package docsync (только тесты) сверяет копии, живущие в двух местах
// репозитория: документация и файл, который она цитирует. Такие инварианты
// объявлены в CLAUDE.md, но компилятором не проверяются и держатся на
// аккуратности — а она уже подводила (R8-qa круг 2, замечание 1).
package docsync

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// TestReadmeUnitMatchesDeployUnit: код-блок `ini` в README.md — дословная копия
// `deploy/apprepo.service` (инвариант CLAUDE.md, раздел «Документация»).
// Разъезжается он молча: сборка цела, тесты зелены, а разворачивают сервис по
// README. Сегодня это комментарий, завтра — `ReadWritePaths=`, то есть старт
// с `status=226/NAMESPACE`.
func TestReadmeUnitMatchesDeployUnit(t *testing.T) {
	// От каталога прогона не зависим: пути считаются от исходника теста.
	_, self, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(self), "..", "..")

	readme := readFile(t, filepath.Join(root, "README.md"))
	unit := readFile(t, filepath.Join(root, "deploy", "apprepo.service"))

	const fence = "```ini\n"
	if n := strings.Count(readme, fence); n != 1 {
		t.Fatalf("в README.md %d код-блоков ```ini, а копия юнита должна быть ровно одна", n)
	}
	_, after, _ := strings.Cut(readme, fence)
	block, _, ok := strings.Cut(after, "\n```")
	if !ok {
		t.Fatal("код-блок ```ini в README.md не закрыт")
	}

	got := strings.Split(block, "\n")
	want := strings.Split(strings.TrimSuffix(unit, "\n"), "\n")
	for i := 0; i < max(len(got), len(want)); i++ {
		g, w := line(got, i), line(want, i)
		if g == w {
			continue
		}
		t.Errorf("строка %d код-блока разошлась с deploy/apprepo.service:\n"+
			"  README.md:              %s\n"+
			"  deploy/apprepo.service: %s", i+1, g, w)
	}
	if t.Failed() {
		t.Log("копия юнита в README обязана меняться вместе с файлом (CLAUDE.md, «Документация»)")
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// line отдаёт строку в кавычках или пометку о её отсутствии: блоки бывают
// разной длины, и «строки нет» читается лучше, чем пустая кавычка.
func line(lines []string, i int) string {
	if i >= len(lines) {
		return "(строки нет)"
	}
	return strconv.Quote(lines[i])
}
