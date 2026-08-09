package platform

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	ok := map[string]string{
		"linux/amd64":    "linux/amd64",
		"Linux/AMD64":    "linux/amd64",
		"  linux/arm64 ": "linux/arm64", // из CI-переменной приезжает с краями
		"darwin/arm64":   "darwin/arm64",
		"windows/386":    "windows/386",
		"freebsd/amd64":  "freebsd/amd64",
		"linux/riscv64":  "linux/riscv64",
		"linux/ppc64le":  "linux/ppc64le",
		"linux/s390x":    "linux/s390x",
		"any":            "any",
		"ANY":            "any",
	}
	for in, want := range ok {
		got, err := Parse(in)
		if err != nil || got != want {
			t.Errorf("Parse(%q) = %q, %v; want %q, nil", in, got, err, want)
		}
	}

	bad := []string{
		"", " ", "amd64", "linux", "linux/", "/amd64", "/",
		"linux/amd64/x", "linux/amd64 extra", "linux\\amd64",
		"plan9/amd64", "linux/sparc", "any/amd64", "anything",
		"linux/am\nd64", // управляющий символ внутри — не край, не обрезается
		"linux\x00/amd64", "li\tnux/amd64",
		strings.Repeat("a", 4096) + "/amd64",
	}
	for _, in := range bad {
		got, err := Parse(in)
		if err == nil {
			t.Errorf("Parse(%q) = %q, nil; want an error", in, got)
			continue
		}
		if got != "" {
			t.Errorf("Parse(%q) returned %q together with an error", in, got)
		}
		// Ошибку показывают пользователю: она обязана перечислить допустимое,
		// включая оба особых значения (R8-sec-round2, N3).
		for _, want := range []string{"linux", "amd64", Any, Universal} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("Parse(%q) error %q does not mention %q", in, err, want)
			}
		}
	}
}

// TestParseLowerBad: "linux/amd64\n" внутри — ошибка, а не тихая нормализация;
// проверяем заодно, что управляющие символы не проходят через ToLower.
func TestKnownListsAreCopies(t *testing.T) {
	for name, get := range map[string]func() []string{"KnownOS": KnownOS, "KnownArch": KnownArch} {
		first := get()
		if len(first) == 0 {
			t.Fatalf("%s() is empty", name)
		}
		first[0] = "mutated"
		if get()[0] == "mutated" {
			t.Errorf("%s() exposes the package dictionary to the caller", name)
		}
	}
	// Списки для UI и Parse обязаны совпадать: каждое имя из списков должно
	// давать валидную пару.
	for _, goos := range KnownOS() {
		for _, goarch := range KnownArch() {
			if _, err := Parse(goos + "/" + goarch); err != nil {
				t.Errorf("Parse(%q/%q) from the UI lists: %v", goos, goarch, err)
			}
		}
	}
}

// TestDetectionConstantsMatchStdlib: определение читает заголовки само и на
// debug/* больше не опирается (F22), поэтому числа в его картах — литералы.
// Здесь debug/elf, debug/macho и debug/pe работают эталоном: разъехаться с
// официальными значениями молча нельзя.
func TestDetectionConstantsMatchStdlib(t *testing.T) {
	if elfMagic != elf.ELFMAG {
		t.Errorf("elfMagic = %q, want %q", elfMagic, elf.ELFMAG)
	}
	for name, pair := range map[string][2]int{
		"EI_CLASS":   {elfEIClass, elf.EI_CLASS},
		"EI_DATA":    {elfEIData, elf.EI_DATA},
		"EI_VERSION": {elfEIVersion, elf.EI_VERSION},
		"EI_OSABI":   {elfEIOSABI, elf.EI_OSABI},
	} {
		if pair[0] != pair[1] {
			t.Errorf("смещение %s = %d, want %d", name, pair[0], pair[1])
		}
	}
	for name, pair := range map[string][2]uint64{
		"ELFCLASS32":       {elfClass32, uint64(elf.ELFCLASS32)},
		"ELFCLASS64":       {elfClass64, uint64(elf.ELFCLASS64)},
		"ELFDATA2LSB":      {elfDataLSB, uint64(elf.ELFDATA2LSB)},
		"ELFDATA2MSB":      {elfDataMSB, uint64(elf.ELFDATA2MSB)},
		"EV_CURRENT":       {elfVersionCurrent, uint64(elf.EV_CURRENT)},
		"ELFOSABI_FREEBSD": {elfOSABIFreeBSD, uint64(elf.ELFOSABI_FREEBSD)},
		"MH_MAGIC":         {machoMagic32, uint64(macho.Magic32)},
		"MH_MAGIC_64":      {machoMagic64, uint64(macho.Magic64)},
		"FAT_MAGIC":        {machoMagicFat, uint64(macho.MagicFat)},
	} {
		if pair[0] != pair[1] {
			t.Errorf("константа %s = %#x, want %#x", name, pair[0], pair[1])
		}
	}
	// e_machine стоит на 0x12 в обеих разрядностях — сверяемся с реальным
	// заголовком, а не с числом из спецификации.
	hdr := elfHeader(elf.ELFCLASS64, elf.ELFDATA2LSB, elf.EM_AARCH64, elf.ELFOSABI_NONE)
	if got := binary.LittleEndian.Uint16(hdr[elfEMachine:]); got != uint16(elf.EM_AARCH64) {
		t.Errorf("e_machine по смещению %#x = %#x, want %#x", elfEMachine, got, uint16(elf.EM_AARCH64))
	}
	// Машины и процессоры: наши литералы против значений stdlib.
	for want, arch := range map[elf.Machine]string{
		elf.EM_X86_64: "amd64", elf.EM_386: "386", elf.EM_AARCH64: "arm64",
		elf.EM_ARM: "arm", elf.EM_RISCV: "riscv64", elf.EM_PPC64: "ppc64le", elf.EM_S390: "s390x",
	} {
		if !hasELFMachine(uint16(want), arch) {
			t.Errorf("elfArch не знает машину %v (%s) под официальным номером %#x", want, arch, uint16(want))
		}
	}
	for cpu, want := range map[macho.Cpu]string{
		macho.CpuAmd64: "amd64", macho.CpuArm64: "arm64", macho.Cpu386: "386", macho.CpuArm: "arm",
	} {
		if got := machoArch[uint32(cpu)]; got != want {
			t.Errorf("machoArch[%v] = %q, want %q", cpu, got, want)
		}
	}
	for machine, want := range map[uint16]string{
		pe.IMAGE_FILE_MACHINE_AMD64: "amd64", pe.IMAGE_FILE_MACHINE_ARM64: "arm64",
		pe.IMAGE_FILE_MACHINE_I386: "386", pe.IMAGE_FILE_MACHINE_ARMNT: "arm",
	} {
		if got := peArch[machine]; got != want {
			t.Errorf("peArch[%#x] = %q, want %q", machine, got, want)
		}
	}
}

func hasELFMachine(machine uint16, arch string) bool {
	for k, v := range elfArch {
		if k.machine == machine && v == arch {
			return true
		}
	}
	return false
}

// TestDetectionMapsMatchDictionary: значения карт определения обязаны быть в
// том же словаре, что и списки для UI, иначе Detect молча вернёт "" на
// опознанном файле (canonical отсеет неизвестное имя).
func TestDetectionMapsMatchDictionary(t *testing.T) {
	var vals []string
	for _, v := range elfArch {
		vals = append(vals, v)
	}
	for _, v := range machoArch {
		vals = append(vals, v)
	}
	for _, v := range peArch {
		vals = append(vals, v)
	}
	for _, v := range vals {
		if !slices.Contains(knownArch, v) {
			t.Errorf("detection map yields arch %q, which KnownArch() does not list", v)
		}
	}
}

// --- Detect: настоящие форматы ---

// elfHeader собирает валидный минимальный ELF-заголовок (без секций и
// сегментов): для определения платформы разборщику этого достаточно.
func elfHeader(class elf.Class, data elf.Data, machine elf.Machine, osabi elf.OSABI) []byte {
	var buf bytes.Buffer
	ident := make([]byte, 16)
	copy(ident, elf.ELFMAG)
	ident[elf.EI_CLASS] = byte(class)
	ident[elf.EI_DATA] = byte(data)
	ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	ident[elf.EI_OSABI] = byte(osabi)
	buf.Write(ident)

	order := binary.ByteOrder(binary.LittleEndian)
	if data == elf.ELFDATA2MSB {
		order = binary.BigEndian
	}
	put16 := func(v uint16) { binary.Write(&buf, order, v) }
	put32 := func(v uint32) { binary.Write(&buf, order, v) }

	put16(uint16(elf.ET_EXEC))
	put16(uint16(machine))
	put32(uint32(elf.EV_CURRENT))
	if class == elf.ELFCLASS64 {
		binary.Write(&buf, order, uint64(0)) // entry
		binary.Write(&buf, order, uint64(0)) // phoff
		binary.Write(&buf, order, uint64(0)) // shoff
	} else {
		put32(0)
		put32(0)
		put32(0)
	}
	put32(0)                     // flags
	put16(uint16(buf.Len() + 6)) // ehsize
	put16(0)                     // phentsize
	put16(0)                     // phnum
	put16(0)                     // shentsize
	put16(0)                     // shnum
	put16(0)                     // shstrndx
	return buf.Bytes()
}

func machoHeader(cpu uint32) []byte {
	var buf bytes.Buffer
	for _, v := range []uint32{
		0xfeedfacf, // MH_MAGIC_64
		cpu,
		0, // cpusubtype
		2, // MH_EXECUTE
		0, // ncmds
		0, // sizeofcmds
		0, // flags
		0, // reserved
	} {
		binary.Write(&buf, binary.LittleEndian, v)
	}
	return buf.Bytes()
}

func peHeader(machine uint16) []byte {
	// 128 байт: pe.NewFile читает 96-байтовый DOS-заголовок целиком, а за ним
	// COFF-заголовок по смещению из него.
	buf := make([]byte, 128)
	copy(buf, "MZ")
	binary.LittleEndian.PutUint32(buf[0x3c:], 0x40) // e_lfanew
	copy(buf[0x40:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(buf[0x44:], machine)
	// NumberOfSections, timestamp, symbol table, symbols, optional header size
	// и characteristics остаются нулями — этого pe.NewFile хватает.
	return buf
}

func write(t *testing.T, name string, b []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustDetect(t *testing.T, path string) string {
	t.Helper()
	got, err := Detect(path)
	if err != nil {
		t.Fatalf("Detect(%s): %v", path, err)
	}
	return got
}

func TestDetectFormats(t *testing.T) {
	cases := []struct {
		name string
		body []byte
		want string
	}{
		{"elf-linux-amd64", elfHeader(elf.ELFCLASS64, elf.ELFDATA2LSB, elf.EM_X86_64, elf.ELFOSABI_NONE), "linux/amd64"},
		{"elf-linux-arm64", elfHeader(elf.ELFCLASS64, elf.ELFDATA2LSB, elf.EM_AARCH64, elf.ELFOSABI_NONE), "linux/arm64"},
		{"elf-linux-386", elfHeader(elf.ELFCLASS32, elf.ELFDATA2LSB, elf.EM_386, elf.ELFOSABI_NONE), "linux/386"},
		{"elf-linux-riscv64", elfHeader(elf.ELFCLASS64, elf.ELFDATA2LSB, elf.EM_RISCV, elf.ELFOSABI_NONE), "linux/riscv64"},
		{"elf-linux-s390x", elfHeader(elf.ELFCLASS64, elf.ELFDATA2MSB, elf.EM_S390, elf.ELFOSABI_NONE), "linux/s390x"},
		{"elf-freebsd-amd64", elfHeader(elf.ELFCLASS64, elf.ELFDATA2LSB, elf.EM_X86_64, elf.ELFOSABI_FREEBSD), "freebsd/amd64"},
		// Машина вне словаря — не опознано, но и не ошибка.
		{"elf-linux-mips", elfHeader(elf.ELFCLASS64, elf.ELFDATA2LSB, elf.EM_MIPS, elf.ELFOSABI_NONE), ""},
		// x32 ABI: та же машина в 32-битном классе — не amd64.
		{"elf-linux-x32", elfHeader(elf.ELFCLASS32, elf.ELFDATA2LSB, elf.EM_X86_64, elf.ELFOSABI_NONE), ""},
		{"macho-darwin-arm64", machoHeader(0x0100000c), "darwin/arm64"},
		{"macho-darwin-amd64", machoHeader(0x01000007), "darwin/amd64"},
		{"pe-windows-amd64", peHeader(0x8664), "windows/amd64"},
		{"pe-windows-arm64", peHeader(0xaa64), "windows/arm64"},
		{"pe-windows-386", peHeader(0x14c), "windows/386"},
		{"pe-unknown-machine", peHeader(0x0166), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := mustDetect(t, write(t, c.name, c.body)); got != c.want {
				t.Errorf("Detect = %q, want %q", got, c.want)
			}
		})
	}
}

// TestDetectRealBinary: тестовый бинарник — настоящий исполняемый файл этой
// платформы, собранный тулчейном. Крафченые заголовки выше проверяют разбор,
// этот тест — что на живом файле ответ совпадает с GOOS/GOARCH.
func TestDetectRealBinary(t *testing.T) {
	want, err := Parse(runtime.GOOS + "/" + runtime.GOARCH)
	if err != nil {
		t.Skipf("хост %s/%s вне словаря", runtime.GOOS, runtime.GOARCH)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	if got := mustDetect(t, exe); got != want {
		t.Errorf("Detect(%s) = %q, want %q", exe, got, want)
	}
}

func TestDetectArchiveIsNotRecognized(t *testing.T) {
	// gzip-заголовок: ровно тот случай, ради которого платформу дают руками.
	if got := mustDetect(t, write(t, "sample.tar.gz", []byte{0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 3, 'x'})); got != "" {
		t.Errorf("Detect(gzip) = %q, want \"\"", got)
	}
	if got := mustDetect(t, write(t, "script.sh", []byte("#!/bin/sh\necho hi\n"))); got != "" {
		t.Errorf("Detect(script) = %q, want \"\"", got)
	}
}

// --- Detect: враждебный ввод ---
//
// Файл сюда приходит от пользователя, и разборщики debug/* — это парсеры
// бинарного формата. Любой из случаев ниже не должен ни ронять процесс паникой,
// ни выедать память; допустимый ответ — "" или ошибка чтения.

func TestDetectHostileInput(t *testing.T) {
	zeros := make([]byte, 4096)
	rnd := make([]byte, 65536)
	rand.New(rand.NewSource(1)).Read(rnd) // фиксированное зерно: тест воспроизводим

	valid := elfHeader(elf.ELFCLASS64, elf.ELFDATA2LSB, elf.EM_X86_64, elf.ELFOSABI_NONE)

	// Заголовок с гигантской таблицей секций в крошечном файле: классическая
	// попытка заставить разборщик выделить память по числу из файла.
	bomb := slices.Clone(valid)
	binary.LittleEndian.PutUint64(bomb[0x28:], 64)     // shoff
	binary.LittleEndian.PutUint16(bomb[0x3a:], 64)     // shentsize
	binary.LittleEndian.PutUint16(bomb[0x3c:], 0xffff) // shnum
	binary.LittleEndian.PutUint16(bomb[0x36:], 0xffff) // phnum
	binary.LittleEndian.PutUint64(bomb[0x20:], 1<<40)  // phoff за пределами файла
	binary.LittleEndian.PutUint16(bomb[0x38:], 0xffff) // phentsize

	cases := map[string][]byte{
		"empty":              {},
		"one-byte":           {0x7f},
		"elf-magic-only":     []byte(elf.ELFMAG),
		"zeros":              zeros,
		"garbage":            rnd,
		"mz-only":            []byte("MZ"),
		"macho-magic-only":   {0xcf, 0xfa, 0xed, 0xfe},
		"section-table-bomb": bomb,
	}
	// Обрезанный ELF-заголовок на каждой длине: где-то там разборщик читает
	// поле, которого уже нет.
	for n := 1; n < len(valid); n++ {
		cases["elf-truncated"] = valid[:n]
		checkHostile(t, "elf-truncated", valid[:n])
	}
	// Валидный заголовок с испорченным байтом в каждой позиции.
	for i := range valid {
		corrupt := slices.Clone(valid)
		corrupt[i] ^= 0xff
		checkHostile(t, "elf-corrupt-byte", corrupt)
	}
	for name, body := range cases {
		checkHostile(t, name, body)
	}
}

// checkHostile: Detect отвечает канонической платформой, "" или ошибкой — и
// никогда не паникует.
func checkHostile(t *testing.T, name string, body []byte) {
	t.Helper()
	path := write(t, name, body)
	got, err := Detect(path)
	if err != nil {
		if strings.Contains(err.Error(), "panic") {
			t.Fatalf("%s: Detect паникует: %v", name, err)
		}
		return
	}
	if got == "" {
		return
	}
	if _, perr := Parse(got); perr != nil {
		t.Errorf("%s: Detect = %q, что не проходит Parse: %v", name, got, perr)
	}
}

func TestDetectSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	if err := os.WriteFile(target,
		elfHeader(elf.ELFCLASS64, elf.ELFDATA2LSB, elf.EM_X86_64, elf.ELFOSABI_NONE), 0o600); err != nil {
		t.Fatal(err)
	}

	// Симлинк на обычный файл — читается как файл: он и есть тот же файл.
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("симлинки недоступны: %v", err)
	}
	if got := mustDetect(t, link); got != "linux/amd64" {
		t.Errorf("Detect(symlink to ELF) = %q, want linux/amd64", got)
	}

	// Симлинк на устройство: не регулярный файл — не разбираем вовсе, иначе
	// чтение заголовка с /dev/zero не закончится никогда.
	dev := filepath.Join(dir, "dev")
	if err := os.Symlink("/dev/zero", dev); err != nil {
		t.Skip(err)
	}
	if got, err := Detect(dev); got != "" || err != nil {
		t.Errorf("Detect(symlink to /dev/zero) = %q, %v; want \"\", nil", got, err)
	}

	// Симлинк в никуда — ошибка чтения, и вызывающий сам решает, что с ней.
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "nope"), dangling); err != nil {
		t.Skip(err)
	}
	if _, err := Detect(dangling); err == nil {
		t.Error("Detect(dangling symlink) = nil error, want a read error")
	}

	// Каталог — тоже не регулярный файл.
	if got, err := Detect(dir); got != "" || err != nil {
		t.Errorf("Detect(dir) = %q, %v; want \"\", nil", got, err)
	}
}

// TestDetectDoesNotReadWholeFile: файл может быть двухгигабайтным архивом, а
// платформа живёт в первых байтах. Меряем выделенную память на файле в 64 MiB —
// чтение целиком тут же вылезет в TotalAlloc.
func TestDetectDoesNotReadWholeFile(t *testing.T) {
	if testing.Short() {
		t.Skip("большой файл — пропускаем в -short")
	}
	const size = 64 << 20
	body := make([]byte, size)
	// Валидный ELF-заголовок впереди: разборщик должен реально работать, а не
	// отвалиться на магии в первых четырёх байтах.
	copy(body, elfHeader(elf.ELFCLASS64, elf.ELFDATA2LSB, elf.EM_X86_64, elf.ELFOSABI_NONE))
	rand.New(rand.NewSource(2)).Read(body[64:])
	path := write(t, "huge.bin", body)
	body = nil

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	got, err := Detect(path)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if got != "linux/amd64" {
		t.Errorf("Detect = %q, want linux/amd64", got)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > size/8 {
		t.Errorf("Detect выделил %d байт на файле в %d — похоже на чтение целиком", alloc, size)
	}
}

// --- Detect: бомбы (R8-sec S1) ---
//
// Прошлые тесты враждебного ввода промахнулись мимо самого дорогого случая:
// `section-table-bomb` в TestDetectHostileInput — файл в 64 байта, и чтение
// таблицы падает на EOF в первую же миллисекунду, а
// TestDetectDoesNotReadWholeFile берёт валидный заголовок и 64 MiB мусора, но
// заголовок никуда не указывает. Опасен третий случай: заголовок, который
// честно указывает внутрь настоящего большого файла. Такому saferio не мешает
// ничем — «столько байт в файле действительно есть», — и 256 MiB превращались
// в 1,1 GiB heap и 8,1 с, а 1 GiB под cgroup-лимитом убивал процесс.
// F22 убрала саму возможность: заголовки читаются напрямую, ни таблица секций,
// ни таблица символов, ни загрузочные команды не читаются вовсе.

// bombFile пишет файл в size байт, у которого настоящие только первые байты
// (hdr), а хвост — дыра: содержимое хвоста разборщику безразлично, а класть в
// тест четверть гигабайта настоящих байтов незачем.
func bombFile(t *testing.T, name string, hdr []byte, size int64) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(hdr); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	return path
}

// elfExtendedShnumHeader: e_shnum == 0 переключает debug/elf на расширенную
// нумерацию — настоящее число секций берётся из sh_size нулевой секции, а это
// 64-битное поле. Указываем им ровно на весь файл: столько байт в файле есть,
// поэтому saferio пропускает чтение, а на каждые 64 байта файла создаётся
// *elf.Section.
func elfExtendedShnumHeader(size int64) []byte {
	b := make([]byte, 128)
	copy(b, elfHeader(elf.ELFCLASS64, elf.ELFDATA2LSB, elf.EM_X86_64, elf.ELFOSABI_NONE))
	le := binary.LittleEndian
	le.PutUint64(b[0x28:], 64)                  // e_shoff: таблица сразу за заголовком
	le.PutUint16(b[0x3a:], 64)                  // e_shentsize
	le.PutUint16(b[0x3c:], 0)                   // e_shnum = 0 → расширенная нумерация
	le.PutUint16(b[0x3e:], 0)                   // e_shstrndx
	le.PutUint64(b[64+32:], uint64(size-64)/64) // sh_size секции 0 = число секций
	return b
}

// elfWholeFileStrtabHeader: второй, независимый вариант той же бомбы — таблица
// имён секций объявлена во весь файл, и Section.Data() честно читает её целиком.
func elfWholeFileStrtabHeader(size int64) []byte {
	b := make([]byte, 192)
	copy(b, elfHeader(elf.ELFCLASS64, elf.ELFDATA2LSB, elf.EM_X86_64, elf.ELFOSABI_NONE))
	le := binary.LittleEndian
	le.PutUint64(b[0x28:], 64)                      // e_shoff
	le.PutUint16(b[0x3a:], 64)                      // e_shentsize
	le.PutUint16(b[0x3c:], 2)                       // e_shnum
	le.PutUint16(b[0x3e:], 1)                       // e_shstrndx
	le.PutUint32(b[128+4:], uint32(elf.SHT_STRTAB)) // секция 1: sh_type
	le.PutUint64(b[128+24:], 0)                     // sh_offset
	le.PutUint64(b[128+32:], uint64(size))          // sh_size — весь файл
	return b
}

// peSymbolBombHeader: PE, объявляющий 4 млрд символов и таблицу строк во весь
// файл. debug/pe вычитывал их целиком — 3,8 с и 439 MB на файле в 64 MiB.
func peSymbolBombHeader(size int64) []byte {
	b := make([]byte, 0x100)
	copy(b, "MZ")
	le := binary.LittleEndian
	le.PutUint32(b[0x3c:], 0x80)
	copy(b[0x80:], "PE\x00\x00")
	le.PutUint16(b[0x84:], 0x8664)     // Machine: amd64
	le.PutUint16(b[0x86:], 1)          // NumberOfSections
	le.PutUint32(b[0x8c:], 0x1000)     // PointerToSymbolTable — внутрь файла
	le.PutUint32(b[0x90:], 0xffffffff) // NumberOfSymbols
	return b
}

// fatBombHeader: fat Mach-O с абсурдным nfat_arch и правдоподобными срезами —
// каждый заявляет 16 MiB загрузочных команд, честно лежащих внутри файла.
// Возвращает заголовок и функцию, дописывающую заголовки срезов в файл.
func fatBombHeader(size int64) ([]byte, func(*os.File)) {
	const n = 64
	b := make([]byte, 8+20*n)
	be, le := binary.BigEndian, binary.LittleEndian
	be.PutUint32(b[0:], 0xcafebabe)
	be.PutUint32(b[4:], 0x7fffffff) // nfat_arch
	offs := make([]int64, n)
	for i := 0; i < n; i++ {
		offs[i] = int64(0x10000 + i*0x1000)
		be.PutUint32(b[8+i*20:], 0x01000007)        // cputype amd64
		be.PutUint32(b[8+i*20+4:], uint32(i))       // cpusubtype — все разные
		be.PutUint32(b[8+i*20+8:], uint32(offs[i])) // offset
		be.PutUint32(b[8+i*20+12:], uint32(size)-uint32(offs[i]))
		be.PutUint32(b[8+i*20+16:], 12)
	}
	return b, func(f *os.File) {
		slice := make([]byte, 24)
		le.PutUint32(slice[0:], 0xfeedfacf) // MH_MAGIC_64
		le.PutUint32(slice[4:], 0x01000007) // cputype
		le.PutUint32(slice[12:], 2)         // MH_EXECUTE
		le.PutUint32(slice[16:], 1)         // ncmds
		le.PutUint32(slice[20:], 16<<20)    // sizeofcmds — 16 MiB
		for i := 0; i < n; i++ {
			le.PutUint32(slice[8:], uint32(i))
			if _, err := f.WriteAt(slice, offs[i]); err != nil {
				panic(err)
			}
		}
	}
}

// TestDetectHostileBombsAreCheap — критерий приёмки F21 и F22: враждебный файл
// на 256 MiB, чей заголовок честно указывает внутрь него, обязан стоить разбору
// миллисекунд и мегабайтов. Форматов три: ELF ловил бомбу таблицей секций,
// PE — таблицей символов, fat Mach-O — числом срезов.
func TestDetectHostileBombsAreCheap(t *testing.T) {
	if testing.Short() {
		t.Skip("файл на 256 MiB — пропускаем в -short")
	}
	const size = 256 << 20
	fatHdr, fillFat := fatBombHeader(size)
	for _, c := range []struct {
		name string
		hdr  []byte
		fill func(*os.File)
	}{
		{"extended-shnum", elfExtendedShnumHeader(size), nil},
		{"whole-file-shstrtab", elfWholeFileStrtabHeader(size), nil},
		{"pe-symbol-table", peSymbolBombHeader(size), nil},
		{"macho-fat-arches", fatHdr, fillFat},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := bombFile(t, "bomb.bin", c.hdr, size)
			if c.fill != nil {
				f, err := os.OpenFile(path, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				c.fill(f)
				f.Close()
			}
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			start := time.Now()
			got, err := Detect(path)
			elapsed := time.Since(start)
			runtime.ReadMemStats(&after)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			alloc := after.TotalAlloc - before.TotalAlloc
			t.Logf("%s: %v, TotalAlloc %d байт => %q", c.name, elapsed, alloc, got)
			// Врёт у этих файлов не заголовок, а таблицы, на которые он
			// указывает; заголовок ELF и PE честно называет amd64, и назвать
			// его — правильный ответ. Проверяется не «не опознано», а цена:
			// раньше те же файлы стоили секунд и гигабайтов.
			if _, perr := Parse(got); got != "" && perr != nil {
				t.Errorf("Detect = %q, что не проходит Parse: %v", got, perr)
			}
			if elapsed > time.Second {
				t.Errorf("Detect занял %v, want < 1 с", elapsed)
			}
			if alloc > 64<<10 {
				t.Errorf("Detect выделил %d байт, want < 64 KiB", alloc)
			}
		})
	}
}

// --- Detect: крупные настоящие бинарники (R8-qa, находка 1) ---
//
// Прежний тест на «настоящем» файле брал os.Executable() и на не-ELF хосте
// молча уходил в t.Skip, а интеграционные фикстуры собирали hello-world в
// полтора мегабайта. Ровно в этот зазор и провалился дефект: у неурезанного
// `go build` таблица символов Mach-O и PE перерастала рубеж чтения примерно с
// 15 MB, и настоящие сборки перестали определяться. Фикстура обязана быть
// крупной, иначе тест зелёный при сломанном определении.

// bigTargets — то, что заведомо крупное и есть в любой установке Go:
// cmd/compile весит 27–29 MB под каждую из трёх платформ.
var bigTargets = []struct{ goos, goarch string }{
	{"darwin", "arm64"}, {"darwin", "amd64"}, {"windows", "amd64"}, {"linux", "amd64"},
}

// buildBig кросс-собирает крупный бинарник тулчейна под tg. Сборки кешируются
// на прогон пакета: под каждую GOARCH Go докомпилирует стандартную библиотеку.
var (
	bigMu    sync.Mutex
	bigCache = map[string]string{}
	bigDir   string
)

func buildBig(t *testing.T, goos, goarch string) string {
	t.Helper()
	bigMu.Lock()
	defer bigMu.Unlock()
	key := goos + "/" + goarch
	if p, ok := bigCache[key]; ok {
		return p
	}
	if bigDir == "" {
		var err error
		if bigDir, err = os.MkdirTemp("", "platform-big"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(bigDir); bigDir, bigCache = "", map[string]string{} })
	}
	out := filepath.Join(bigDir, "compile-"+goos+"-"+goarch)
	cmd := exec.Command("go", "build", "-o", out, "cmd/compile")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch, "GOFLAGS=")
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("go build cmd/compile под %s: %v\n%s", key, err, msg)
	}
	bigCache[key] = out
	return out
}

// TestDetectBigRealBinaries: неурезанный `go build` крупного пакета под darwin,
// windows и linux обязан определяться. Это и есть обещание волны 8 «CI-скрипты
// с бинарниками не правятся ни одной строкой».
func TestDetectBigRealBinaries(t *testing.T) {
	if testing.Short() {
		t.Skip("кросс-сборка — пропускаем в -short")
	}
	for _, tg := range bigTargets {
		t.Run(tg.goos+"/"+tg.goarch, func(t *testing.T) {
			path := buildBig(t, tg.goos, tg.goarch)
			st, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if st.Size() < 15<<20 {
				t.Fatalf("фикстура весит %d байт: дефект, который тест ловит, начинается примерно с 15 MB", st.Size())
			}
			want := tg.goos + "/" + tg.goarch
			start := time.Now()
			got := mustDetect(t, path)
			t.Logf("%s: %d байт, %v", want, st.Size(), time.Since(start).Round(time.Microsecond))
			if got != want {
				t.Errorf("Detect настоящей сборки = %q, want %q", got, want)
			}
		})
	}
}

// TestDetectBigUniversal: настоящий universal binary из двух крупных срезов.
// Раньше срезы делили один рубеж чтения, и порог на срез был вдвое ниже
// (R8-sec-round2, S4 «закрыто частично»).
func TestDetectBigUniversal(t *testing.T) {
	if testing.Short() {
		t.Skip("кросс-сборка — пропускаем в -short")
	}
	var parts [][]byte
	for _, goarch := range []string{"amd64", "arm64"} {
		b, err := os.ReadFile(buildBig(t, "darwin", goarch))
		if err != nil {
			t.Fatal(err)
		}
		parts = append(parts, b)
	}
	path := write(t, "universal", fatOf(parts...))
	if got := mustDetect(t, path); got != Universal {
		t.Errorf("Detect настоящего universal binary = %q, want %q", got, Universal)
	}
}

// TestDetectReadsHeaderOnly: сколько байт Detect читает из файла. Стоимость
// разбора обязана не зависеть от размера — именно это и сломалось в F21, когда
// debug/macho и debug/pe читали таблицу символов целиком (5 % файла).
func TestDetectReadsHeaderOnly(t *testing.T) {
	files := map[string][]byte{
		"elf":   elfHeader(elf.ELFCLASS64, elf.ELFDATA2LSB, elf.EM_X86_64, elf.ELFOSABI_NONE),
		"macho": machoHeader(0x0100000c),
		"pe":    peHeader(0x8664),
		"fat":   fatMachO(0x01000007, 0x0100000c),
	}
	if !testing.Short() {
		for _, tg := range bigTargets {
			b, err := os.ReadFile(buildBig(t, tg.goos, tg.goarch))
			if err != nil {
				t.Fatal(err)
			}
			files["big-"+tg.goos+"-"+tg.goarch] = b
		}
	}
	for name, body := range files {
		c := &countingReaderAt{r: bytes.NewReader(body)}
		got := detect(c)
		t.Logf("%-20s размер %-9d прочитано %d байт => %q", name, len(body), c.n, got)
		if got == "" {
			t.Errorf("%s: Detect = \"\"", name)
		}
		// Потолок — префикс заголовка плюс заголовки срезов fat: меньше
		// килобайта на файл любого размера.
		if c.n > 1<<10 {
			t.Errorf("%s: Detect прочитал %d байт, want < 1 KiB", name, c.n)
		}
	}
}

type countingReaderAt struct {
	r io.ReaderAt
	n int64
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.r.ReadAt(p, off)
	c.n += int64(n)
	return n, err
}

// TestDetectConcurrent: стоимость разбора плоская, поэтому одновременные
// заливки больше не складываются в мегабайты (R8-sec-round2, N2 — там 128
// параллельных разборов давали +5 MiB каждый и подводили процесс к
// MemoryMax=1G). Ограничивать параллелизм после F22 незачем, и этот тест —
// то, что заметит возврат прежней стоимости.
func TestDetectConcurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("файл на 64 MiB — пропускаем в -short")
	}
	const n, size = 128, 64 << 20
	hdr, fill := fatBombHeader(size)
	path := bombFile(t, "bomb.bin", hdr, size)
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	fill(f)
	f.Close()

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got, err := Detect(path); got != "" || err != nil {
				t.Errorf("Detect = %q, %v; want \"\", nil", got, err)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	alloc := after.TotalAlloc - before.TotalAlloc
	t.Logf("%d одновременных Detect: %v, TotalAlloc %d байт (%d на разбор)", n, elapsed, alloc, alloc/n)
	if alloc > 4<<20 {
		t.Errorf("%d одновременных Detect выделили %d байт, want < 4 MiB", n, alloc)
	}
	if elapsed > 5*time.Second {
		t.Errorf("%d одновременных Detect заняли %v, want < 5 с", n, elapsed)
	}
}

// fatMachO собирает настоящий macOS universal binary: fat-заголовок и по срезу
// на каждую архитектуру.
func fatMachO(cpus ...uint32) []byte {
	parts := make([][]byte, len(cpus))
	for i, cpu := range cpus {
		parts[i] = machoHeader(cpu)
	}
	return fatOf(parts...)
}

// fatOf упаковывает готовые срезы Mach-O в fat-контейнер — то же, что делает
// lipo. Срезом может быть и крафченый заголовок, и настоящий `go build`.
func fatOf(parts ...[]byte) []byte {
	const align = 1 << 14
	off := (8 + 20*len(parts) + align - 1) &^ (align - 1)
	b := make([]byte, off)
	be := binary.BigEndian
	be.PutUint32(b[0:], 0xcafebabe) // MagicFat
	be.PutUint32(b[4:], uint32(len(parts)))
	for i, slice := range parts {
		be.PutUint32(b[8+i*20:], binary.LittleEndian.Uint32(slice[4:]))   // cputype
		be.PutUint32(b[8+i*20+4:], binary.LittleEndian.Uint32(slice[8:])) // cpusubtype
		be.PutUint32(b[8+i*20+8:], uint32(len(b)))
		be.PutUint32(b[8+i*20+12:], uint32(len(slice)))
		be.PutUint32(b[8+i*20+16:], 14) // align = 2^14
		b = append(b, slice...)
		b = append(b, make([]byte, (len(b)+align-1)&^(align-1)-len(b))...)
	}
	return b
}

// TestDetectFatMachO: до F21 настоящий universal binary не определялся вовсе
// (macho.NewFile fat-магию не понимает), и волна 8 стала такие файлы
// отклонять — R8-sec S4.
func TestDetectFatMachO(t *testing.T) {
	if got := mustDetect(t, write(t, "universal", fatMachO(0x01000007, 0x0100000c))); got != Universal {
		t.Errorf("Detect(fat amd64+arm64) = %q, want %q", got, Universal)
	}
	// Один срез — обычный Mach-O в fat-обёртке; врать про universal незачем.
	if got := mustDetect(t, write(t, "single", fatMachO(0x0100000c))); got != "darwin/arm64" {
		t.Errorf("Detect(fat arm64) = %q, want darwin/arm64", got)
	}
	// Значение из Detect обязано проходить Parse, иначе его нельзя ни ввести
	// руками, ни сверить с ?platform=.
	if got, err := Parse(Universal); err != nil || got != Universal {
		t.Errorf("Parse(%q) = %q, %v; want %q, nil", Universal, got, err, Universal)
	}
}
