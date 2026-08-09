package app

// T24: backfill платформы для версий, залитых до её появления.

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"apprepo/internal/config"
	"apprepo/internal/files"
	"apprepo/internal/store"
)

// elfBinary — минимальный валидный ELF-заголовок нужной машины: backfill
// смотрит только в заголовок, тело файла ему не нужно.
func elfBinary(machine elf.Machine) []byte {
	var buf bytes.Buffer
	ident := make([]byte, 16)
	copy(ident, elf.ELFMAG)
	ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	buf.Write(ident)
	binary.Write(&buf, binary.LittleEndian, uint16(elf.ET_EXEC))
	binary.Write(&buf, binary.LittleEndian, uint16(machine))
	binary.Write(&buf, binary.LittleEndian, uint32(elf.EV_CURRENT))
	for i := 0; i < 3; i++ {
		binary.Write(&buf, binary.LittleEndian, uint64(0)) // entry, phoff, shoff
	}
	binary.Write(&buf, binary.LittleEndian, uint32(0))  // flags
	binary.Write(&buf, binary.LittleEndian, uint16(64)) // ehsize
	for i := 0; i < 5; i++ {
		binary.Write(&buf, binary.LittleEndian, uint16(0))
	}
	return buf.Bytes()
}

// seed раскладывает версию по диску и в БД так, как это делает заливка.
func seed(t *testing.T, st *store.Store, fst *files.Storage, app, version, filename string, body []byte) {
	t.Helper()
	a, err := st.GetApp(app)
	if err != nil {
		t.Fatal(err)
	}
	if a == nil {
		if a, err = st.CreateApp(app, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.CreateVersion(a.ID, version, filename, int64(len(body)), "ab"); err != nil {
		t.Fatal(err)
	}
	path := fst.Path(app, version, filename)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if body != nil {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func platformOf(t *testing.T, st *store.Store, app, version string) string {
	t.Helper()
	a, err := st.GetApp(app)
	if err != nil || a == nil {
		t.Fatalf("GetApp(%q) = %v, %v", app, a, err)
	}
	v, err := st.GetVersion(a.ID, version)
	if err != nil || v == nil {
		t.Fatalf("GetVersion(%q) = %v, %v", version, v, err)
	}
	return v.Platform
}

// newApp поднимает приложение на временном каталоге и отдаёт store; лог
// перехвачен, чтобы проверить итоговую строку backfill.
func newApp(t *testing.T, dir string) (*store.Store, string) {
	t.Helper()
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	_, st, err := New(config.Config{
		DataDir:        dir,
		DBPath:         filepath.Join(dir, "apprepo.db"),
		MaxUploadBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st, logged.String()
}

func TestBackfillPlatforms(t *testing.T) {
	dir := t.TempDir()

	// Первый старт создаёт схему; версии кладём уже в готовую БД, как если бы
	// их залили до появления платформы.
	st, logged := newApp(t, dir)
	if strings.Contains(logged, "backfill") {
		t.Errorf("пустая БД: backfill не должен ничего писать в лог, получено %q", logged)
	}
	fst := &files.Storage{Root: dir}
	seed(t, st, fst, "srv", "1.0.0", "srv-linux-amd64", elfBinary(elf.EM_X86_64))
	seed(t, st, fst, "srv", "1.1.0", "srv-linux-arm64", elfBinary(elf.EM_AARCH64))
	seed(t, st, fst, "srv", "1.2.0", "srv.tar.gz", []byte{0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0}) // архив
	seed(t, st, fst, "srv", "1.3.0", "srv-broken", []byte("\x7fELFgarbage"))                // битый
	seed(t, st, fst, "srv", "1.4.0", "srv-missing", nil)                                    // файла нет
	st.Close()

	// Второй старт — тот, на котором backfill и работает.
	st, logged = newApp(t, dir)
	want := map[string]string{
		"1.0.0": "linux/amd64",
		"1.1.0": "linux/arm64",
		"1.2.0": "", // архив: платформа проставляется руками
		"1.3.0": "",
		"1.4.0": "",
	}
	for version, p := range want {
		if got := platformOf(t, st, "srv", version); got != p {
			t.Errorf("платформа %s = %q, want %q", version, got, p)
		}
	}
	// Ровно одна итоговая строка, а не строка на версию.
	if n := strings.Count(logged, "platform backfill"); n != 1 {
		t.Errorf("строк backfill в логе: %d, want 1; лог: %q", n, logged)
	}
	if !strings.Contains(logged, "checked 5 version(s), set 2, skipped 3") {
		t.Errorf("итоговая строка backfill: %q", logged)
	}
	st.Close()

	// Третий старт: проставленное не трогается, проверяются только пустые, и
	// на неопознаваемых файлах повторный прогон так же безопасен.
	st, logged = newApp(t, dir)
	if got := platformOf(t, st, "srv", "1.0.0"); got != "linux/amd64" {
		t.Errorf("платформа после перезапуска = %q", got)
	}
	if !strings.Contains(logged, "checked 3 version(s), set 0, skipped 3") {
		t.Errorf("повторный прогон: %q", logged)
	}
}

// TestBackfillIgnoresHostileFile: файл, который валит разборщик, не должен
// валить старт — версия просто остаётся без платформы.
func TestBackfillIgnoresHostileFile(t *testing.T) {
	dir := t.TempDir()
	st, _ := newApp(t, dir)
	fst := &files.Storage{Root: dir}

	// Заголовок с гигантской таблицей секций и смещениями за пределы файла.
	bomb := elfBinary(elf.EM_X86_64)
	binary.LittleEndian.PutUint64(bomb[0x28:], 64)     // shoff
	binary.LittleEndian.PutUint16(bomb[0x3a:], 64)     // shentsize
	binary.LittleEndian.PutUint16(bomb[0x3c:], 0xffff) // shnum
	seed(t, st, fst, "srv", "1.0.0", "bomb", bomb)
	seed(t, st, fst, "srv", "2.0.0", "zeros", make([]byte, 4096))
	st.Close()

	st, logged := newApp(t, dir)
	for _, v := range []string{"1.0.0", "2.0.0"} {
		if got := platformOf(t, st, "srv", v); got != "" {
			// Не ошибка сама по себе (заголовок мог оказаться разбираемым),
			// но значение обязано быть каноническим.
			if !strings.Contains(got, "/") {
				t.Errorf("версия %s получила платформу %q", v, got)
			}
		}
	}
	if !strings.Contains(logged, "platform backfill") {
		t.Errorf("backfill не отработал: %q", logged)
	}
}

// TestBackfillStopsAtTimeBudget: старт не должен зависеть от содержимого
// data-dir. Прямо измерить это дорого (нужны десятки тысяч версий), поэтому
// проверяем сам рубеж: с нулевым бюджетом backfill не разбирает ни одного
// файла, отвечает мгновенно и говорит об этом в лог.
func TestBackfillStopsAtTimeBudget(t *testing.T) {
	dir := t.TempDir()
	st, _ := newApp(t, dir)
	fst := &files.Storage{Root: dir}
	for _, v := range []string{"1.0.0", "2.0.0"} {
		seed(t, st, fst, "app", v, "bin", elfBinary(elf.EM_X86_64))
	}

	defer func(saved time.Duration) { backfillBudget = saved }(backfillBudget)
	backfillBudget = -1 // бюджет исчерпан ещё до первой версии

	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	backfillPlatforms(st, fst)

	if p := platformOf(t, st, "app", "1.0.0"); p != "" {
		t.Errorf("платформа проставлена вопреки исчерпанному бюджету: %q", p)
	}
	if !strings.Contains(logged.String(), "stopped after") {
		t.Errorf("в логе нет отметки об остановке по бюджету: %q", logged.String())
	}
}
