package integration

// Критерии приёмки F21 (проверочная волна 8): платформа решается по временному
// файлу ДО публикации, поэтому отказ по ней не создаёт на диске вообще ничего,
// а удаление приложения в это же окно не приводит к 500 (R8-sec S2).

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// elfAmd64Bytes — валидный заголовок ELF64 linux/amd64, дополненный нулями до
// size байт: platform.Detect читает только заголовок, а хвост нужен затем,
// чтобы тело заливки было заметного размера.
func elfAmd64Bytes(size int) []byte {
	var buf bytes.Buffer
	ident := make([]byte, 16)
	copy(ident, elf.ELFMAG)
	ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	buf.Write(ident)
	put := func(v any) { binary.Write(&buf, binary.LittleEndian, v) }
	put(uint16(elf.ET_EXEC))
	put(uint16(elf.EM_X86_64))
	put(uint32(elf.EV_CURRENT))
	put(uint64(0)) // entry
	put(uint64(0)) // phoff
	put(uint64(0)) // shoff — секций нет, дальше заголовка разбор не идёт
	put(uint32(0)) // flags
	put(uint16(64))
	for i := 0; i < 5; i++ { // phentsize, phnum, shentsize, shnum, shstrndx
		put(uint16(0))
	}
	b := buf.Bytes()
	if size <= len(b) {
		return b
	}
	return append(b, make([]byte, size-len(b))...)
}

// TestPlatformRefusalCreatesNothingOnDisk: до F21 тело успевало опубликоваться
// и убиралось откатом — каталог приложения после отказа оставался. Теперь
// публикации нет вовсе, поэтому проверяем сильное утверждение: в data-dir не
// появилось ни каталога приложения, ни временного файла.
func TestPlatformRefusalCreatesNothingOnDisk(t *testing.T) {
	for _, c := range []struct {
		name  string
		query string
		body  []byte
		code  int
		text  string
	}{
		{"архив без платформы", "", []byte("archive-bytes-not-a-binary"),
			http.StatusBadRequest, "platform_required"},
		{"метка против содержимого", "&platform=windows/amd64", elfAmd64Bytes(4096),
			http.StatusConflict, "platform_mismatch"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, 1<<20)
			e.createApp("lab")
			resp := e.api("PUT", "/api/apps/lab/versions/1.0.0?filename=lab-1.0.0"+c.query,
				bytes.NewReader(c.body), nil)
			defer resp.Body.Close()
			body := readBody(t, resp)
			if resp.StatusCode != c.code {
				t.Fatalf("status = %d, want %d; body: %s", resp.StatusCode, c.code, body)
			}
			if !strings.Contains(body, c.text) {
				t.Errorf("в ответе нет %q; body: %s", c.text, body)
			}
			// Каталог приложения создаёт только Upload.Commit, а до него дело
			// не дошло: отказ обязан не оставить в data-dir ни следа.
			mustNotExist(t, e.appDir("lab"), "app directory after a refused upload")
			e.wantNoTempLeftovers()
			if dirs := e.topLevelDirs(); len(dirs) != 0 {
				t.Errorf("data dir holds %v, want nothing", dirs)
			}
		})
	}
}

// TestDeleteAppDuringUploadIsNot500: приложение удаляют, пока заливка в полёте.
// Раньше окно между публикацией файла и созданием строки в БД включало разбор
// файла и на 200 MiB растягивалось до секунд — попадание в него давало 500 и
// FOREIGN KEY constraint failed. Разбор уехал до публикации, окно вернулось к
// прежней ширине, и исход обязан быть отказом клиенту, а не сбоем сервера.
func TestDeleteAppDuringUploadIsNot500(t *testing.T) {
	e := newEnv(t, 1<<20)
	e.createApp("lab")

	release := make(chan struct{})
	// Пауза снимается даже при падении теста: иначе тело остаётся
	// недописанным и httptest.Server.Close виснет в t.Cleanup (F20).
	unpause := sync.OnceFunc(func() { close(release) })
	defer unpause()
	body := &pausedBody{
		head:    elfAmd64Bytes(4096),
		tail:    []byte("tail"),
		release: release,
	}
	done := make(chan *http.Response, 1)
	go func() {
		done <- e.api("PUT", "/api/apps/lab/versions/2.0.0?filename=lab-2.0.0", body, nil)
	}()

	e.waitForTempBytes(int64(len(body.head)))
	del := e.api("DELETE", "/api/apps/lab", nil, nil)
	del.Body.Close()
	if del.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /api/apps/lab: status = %d, want 204", del.StatusCode)
	}
	unpause()

	up := <-done
	defer up.Body.Close()
	if up.StatusCode >= 500 {
		t.Fatalf("PUT during delete: status = %d, want a 4xx refusal; body: %s",
			up.StatusCode, readBody(t, up))
	}
	mustNotExist(t, e.appDir("lab"), "app directory after the app was deleted")
	e.wantNoTempLeftovers()
}
