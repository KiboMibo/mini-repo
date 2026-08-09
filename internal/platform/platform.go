// Package platform describes what a version's binary was built for: a
// canonical "os/arch" string such as "linux/amd64", either detected from the
// file itself or set by hand.
//
// Одна архитектура без ОС двусмысленна — бинарь под linux/amd64 и под
// windows/amd64 не взаимозаменяемы, — поэтому хранится пара. Пустая строка
// означает «неизвестно» и допустима везде: старые версии, залитые до появления
// платформы, и архивы, в которых определять нечего, живут именно так.
package platform

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"syscall"
)

// Any — платформа сборки, которая от ОС и архитектуры не зависит (архив со
// скриптами, jar). Ставится только руками: определить «независимость» по файлу
// нельзя, а угадывать её по «не опознано» — значит выдавать чужой бинарь за
// переносимый.
const Any = "any"

// Universal — настоящий macOS universal binary (fat Mach-O): в одном файле
// несколько срезов под разные архитектуры, и любая одна пара была бы ложью.
// Значение особое, как и Any: пары «os/arch» из словаря оно не образует,
// поэтому Parse узнаёт его отдельной строкой, а в списки KnownOS/KnownArch оно
// не входит — руками такое не выбирают, оно только определяется по файлу
// (иначе в списках завелись бы бессмысленные пары вроде linux/universal).
const Universal = "darwin/universal"

// Словарь платформ — единственный на пакет: из него берут значения Parse,
// карты определения ниже и списки для UI. Имена как у GOOS/GOARCH, чтобы
// строка из репозитория подставлялась в скрипты сборки без перевода.
var (
	knownOS   = []string{"linux", "darwin", "windows", "freebsd"}
	knownArch = []string{"amd64", "arm64", "386", "arm", "riscv64", "ppc64le", "s390x"}
)

// KnownOS returns the accepted OS names, for UI dropdowns.
func KnownOS() []string { return slices.Clone(knownOS) }

// KnownArch returns the accepted architecture names, for UI dropdowns.
func KnownArch() []string { return slices.Clone(knownArch) }

// Parse validates a hand-entered platform and returns its canonical form:
// "os/arch" out of the dictionary above, or Any. Case is folded and the edges
// are trimmed (a value from a CI variable arrives with a stray newline often
// enough), everything else is rejected: a bare "amd64", an empty half
// ("linux/"), a third element, an unknown name, control characters.
//
// Пустая строка — ошибка, а не «неизвестно»: сброс платформы делается не через
// Parse, а прямым store.SetVersionPlatform(id, ""). Текст ошибки перечисляет
// допустимые значения — он показывается пользователю как есть.
func Parse(s string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	if v == Any || v == Universal {
		return v, nil
	}
	if goos, goarch, ok := strings.Cut(v, "/"); ok &&
		slices.Contains(knownOS, goos) && slices.Contains(knownArch, goarch) {
		return goos + "/" + goarch, nil
	}
	return "", fmt.Errorf("invalid platform %q: expected %q or %q, or os/arch where os is one of %s and arch is one of %s",
		s, Any, Universal, strings.Join(knownOS, ", "), strings.Join(knownArch, ", "))
}

// canonical joins a detected pair and checks it against the dictionary, so a
// value that only the detection maps know about cannot leak out into the
// database and diverge from the UI lists.
func canonical(goos, goarch string) string {
	p, err := Parse(goos + "/" + goarch)
	if err != nil {
		return ""
	}
	return p
}

// --- Определение по заголовку ---
//
// Всё, что определению нужно, лежит в первых байтах файла: класс, порядок
// байт, OS/ABI и машина в ELF, тип процессора в Mach-O, машина COFF в PE.
// Таблицы секций, загрузочные команды и таблицы символов не дают ни одного
// используемого поля, поэтому разборщики debug/elf, debug/macho и debug/pe
// здесь не участвуют вовсе (F22): они вычитывали таблицу символов целиком,
// линейно по размеру файла, и настоящие сборки под darwin и windows крупнее
// ~15 MB переставали определяться под рубежом чтения (R8-qa, находка 1;
// R8-sec-round2, N1). Заодно из обработки недоверенного ввода ушли три
// парсера stdlib: осталось чтение полей по фиксированным смещениям.

// headerBytes — префикс, которого хватает любому из четырёх заголовков:
// 64 байта ELF64, 32 байта mach_header_64, 8 байт fat-заголовка и 96 байт
// DOS-заголовка PE (столько же читает debug/pe, прежде чем прыгнуть по
// e_lfanew). Полный разбор укладывается в этот префикс плюс до
// 20·maxFatArch + 4·maxFatArch байт заголовков срезов fat Mach-O и 6 байт
// COFF-заголовка PE — меньше килобайта на файл любого размера.
const headerBytes = 96

// Смещения и константы ELF (e_ident одинаков в обеих разрядностях, e_machine
// стоит на 0x12 и там, и там). Числа сверяются с debug/elf в тестах.
const (
	elfMagic     = "\x7fELF"
	elfEIClass   = 4
	elfEIData    = 5
	elfEIVersion = 6
	elfEIOSABI   = 7
	elfEMachine  = 0x12

	elfClass32, elfClass64 = 1, 2
	elfDataLSB, elfDataMSB = 1, 2
	elfVersionCurrent      = 1
	elfOSABIFreeBSD        = 9

	// Размер заголовка: короче — не ELF, а обрубок, и debug/elf такой файл
	// тоже отвергал.
	elfHeaderSize32, elfHeaderSize64 = 52, 64
)

// Магии Mach-O (little-endian, как их читает debug/macho) и fat Mach-O
// (big-endian). Порядок байт у fat-заголовка обратный не по недосмотру: так
// устроен формат.
const (
	machoMagic32  = 0xfeedface
	machoMagic64  = 0xfeedfacf
	machoMagicFat = 0xcafebabe

	machoHeaderSize32, machoHeaderSize64 = 28, 32

	// maxFatArch — потолок на число срезов universal binary. Без него
	// nfat_arch из файла (до 4 млрд) снова превращал бы разбор в бомбу.
	// У настоящих сборок срезов два-три; тридцать два — заведомый запас.
	maxFatArch  = 32
	fatArchSize = 20 // cputype, cpusubtype, offset, size, align
)

// Смещения PE: сигнатура MZ, указатель на заголовок и машина сразу за "PE\0\0".
const (
	peSignature  = "PE\x00\x00"
	peLfanew     = 0x3c
	peDOSHeader  = 96
	peCOFFPrefix = 6 // "PE\0\0" + Machine
)

// elfKey is machine plus class plus byte order: EM_X86_64 is amd64 only in the
// 64-bit class (the x32 ABI shares the machine), EM_PPC64 is ppc64le only
// little-endian, and neither x32 nor big-endian ppc64 is in the dictionary.
type elfKey struct {
	machine     uint16
	class, data byte
}

var elfArch = map[elfKey]string{
	{0x3e, elfClass64, elfDataLSB}: "amd64",   // EM_X86_64
	{0x03, elfClass32, elfDataLSB}: "386",     // EM_386
	{0xb7, elfClass64, elfDataLSB}: "arm64",   // EM_AARCH64
	{0x28, elfClass32, elfDataLSB}: "arm",     // EM_ARM
	{0xf3, elfClass64, elfDataLSB}: "riscv64", // EM_RISCV
	{0x15, elfClass64, elfDataLSB}: "ppc64le", // EM_PPC64
	{0x16, elfClass64, elfDataMSB}: "s390x",   // EM_S390
}

var machoArch = map[uint32]string{
	0x01000007: "amd64", // CpuAmd64
	0x0100000c: "arm64", // CpuArm64
	0x00000007: "386",   // Cpu386
	0x0000000c: "arm",   // CpuArm
}

var peArch = map[uint16]string{
	0x8664: "amd64", // IMAGE_FILE_MACHINE_AMD64
	0xaa64: "arm64", // IMAGE_FILE_MACHINE_ARM64
	0x014c: "386",   // IMAGE_FILE_MACHINE_I386
	0x01c4: "arm",   // IMAGE_FILE_MACHINE_ARMNT — 32-битный windows/arm
}

// Detect reports the platform of the file at path, or "" (without an error)
// when the format is not one it knows: an archive, a script, a binary for a
// machine outside the dictionary. An error means the file could not be read at
// all; a caller that only wants a best guess may treat it like "".
//
// Вход враждебный: это ровно тот файл, который залил пользователь. Отсюда
// рубежи. Объём работы не зависит от размера файла вовсе — читаются
// фиксированные поля заголовка (см. headerBytes). Открытие неблокирующее, и
// нерегулярный файл (каталог, FIFO, устройство) не разбирается вовсе.
func Detect(path string) (_ string, err error) {
	// O_NONBLOCK: без него открытие FIFO ждёт писателя вечно и до проверки
	// IsRegular дело не доходит — стартовый backfill на подложенном в data-dir
	// FIFO не возвращался никогда (R8-sec S3). На обычные файлы флаг не влияет.
	//
	// За симлинком идём осознанно (O_NOFOLLOW не ставим): по HTTP симлинк в
	// data-dir не создаётся — публикация это os.Link с готового временного
	// файла, — а положенный оператором симлинк на настоящий бинарник разумно
	// разобрать. Наружу из Detect всё равно уходит только значение словаря.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", nil
	}

	defer func() {
		// Страховка, а не основная защита: разбор ниже — это чтение полей по
		// фиксированным смещениям с проверкой длины, паниковать там нечему.
		// Но файл недоверенный, а цена рубежа — три строки против упавшего
		// сервиса на одной кривой загрузке.
		if r := recover(); r != nil {
			err = fmt.Errorf("detect platform: panic while parsing %s: %v", path, r)
		}
	}()
	return detect(f), nil
}

// prefix reads up to len(p) bytes at off and returns what actually was there:
// короткий файл — не ошибка, а просто «нечего разбирать». Смещение может
// приехать из самого файла (e_lfanew, offset среза fat), поэтому чтение за
// концом — штатный случай, а не исключение.
func prefix(r io.ReaderAt, p []byte, off int64) []byte {
	n, _ := r.ReadAt(p, off)
	return p[:n]
}

// detect распознаёт формат по магии в первых байтах и читает из заголовка ровно
// те поля, которые попадают в словарь.
func detect(r io.ReaderAt) string {
	var buf [headerBytes]byte
	h := prefix(r, buf[:], 0)
	switch {
	case len(h) >= elfHeaderSize32 && string(h[:4]) == elfMagic:
		return detectELF(h)
	// Fat Mach-O пробуется до обычного: его магия своя, и настоящий universal
	// binary иначе отклонялся бы как «не опознано» (R8-sec S4).
	case len(h) >= 8 && binary.BigEndian.Uint32(h) == machoMagicFat:
		return detectFatMachO(r, h)
	case len(h) >= machoHeaderSize32 && isMachO(binary.LittleEndian.Uint32(h)):
		return detectMachO(h)
	case len(h) >= peDOSHeader && h[0] == 'M' && h[1] == 'Z':
		return detectPE(r, h)
	}
	return ""
}

func isMachO(magic uint32) bool { return magic == machoMagic32 || magic == machoMagic64 }

// detectELF: ОС в ELF не записана — Go помечает freebsd через OSABI, всё
// остальное приезжает как ELFOSABI_NONE, и это в нашем словаре linux.
func detectELF(h []byte) string {
	class, data := h[elfEIClass], h[elfEIData]
	size := elfHeaderSize32
	if class == elfClass64 {
		size = elfHeaderSize64
	}
	if len(h) < size || h[elfEIVersion] != elfVersionCurrent {
		return ""
	}
	order := binary.ByteOrder(binary.LittleEndian)
	if data == elfDataMSB { // s390x — big-endian, и e_machine у него перевёрнут
		order = binary.BigEndian
	}
	goos := "linux"
	if h[elfEIOSABI] == elfOSABIFreeBSD {
		goos = "freebsd"
	}
	return canonical(goos, elfArch[elfKey{order.Uint16(h[elfEMachine:]), class, data}])
}

func detectMachO(h []byte) string {
	if binary.LittleEndian.Uint32(h) == machoMagic64 && len(h) < machoHeaderSize64 {
		return ""
	}
	return canonical("darwin", machoArch[binary.LittleEndian.Uint32(h[4:])])
}

// detectFatMachO: fat-заголовок целиком big-endian — магия, число срезов и по
// 20 байт на срез. Архитектура берётся из заголовков срезов, внутрь самих
// срезов заходить незачем.
func detectFatMachO(r io.ReaderAt, h []byte) string {
	n := binary.BigEndian.Uint32(h[4:])
	if n < 1 || n > maxFatArch {
		return ""
	}
	arches := prefix(r, make([]byte, fatArchSize*n), 8)
	if uint32(len(arches)) < fatArchSize*n {
		return ""
	}
	// Каждый срез обязан оказаться настоящим Mach-O. Проверка не формальность:
	// 0xcafebabe — заодно магия class-файла Java, у которого на месте nfat_arch
	// стоит номер версии, и без неё .class выдавался бы за universal binary.
	var magic [4]byte
	for i := uint32(0); i < n; i++ {
		off := int64(binary.BigEndian.Uint32(arches[i*fatArchSize+8:]))
		if len(prefix(r, magic[:], off)) < 4 || !isMachO(binary.LittleEndian.Uint32(magic[:])) {
			return ""
		}
	}
	if n == 1 { // один срез — это обычный Mach-O в fat-обёртке
		return canonical("darwin", machoArch[binary.BigEndian.Uint32(arches)])
	}
	return Universal
}

// detectPE: e_lfanew из DOS-заголовка указывает на сигнатуру "PE\0\0", а сразу
// за ней стоит первое поле COFF-заголовка — Machine.
func detectPE(r io.ReaderAt, h []byte) string {
	var coff [peCOFFPrefix]byte
	off := int64(binary.LittleEndian.Uint32(h[peLfanew:])) // uint32 — за пределы int64 не вылезет
	if len(prefix(r, coff[:], off)) < peCOFFPrefix || string(coff[:4]) != peSignature {
		return ""
	}
	return canonical("windows", peArch[binary.LittleEndian.Uint16(coff[4:])])
}
