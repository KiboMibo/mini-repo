package naming

import (
	"strings"
	"testing"
)

func TestValidateAppName(t *testing.T) {
	valid := []string{"a", "myapp", "My-App_1.0", "0app", strings.Repeat("a", 64)}
	for _, name := range valid {
		if err := ValidateAppName(name); err != nil {
			t.Errorf("ValidateAppName(%q) = %v, want nil", name, err)
		}
	}
	invalid := []string{"", "latest", "../x", "a/b", ".hidden", "-app", "a b", strings.Repeat("a", 65)}
	for _, name := range invalid {
		if err := ValidateAppName(name); err == nil {
			t.Errorf("ValidateAppName(%q) = nil, want error", name)
		}
	}
}

func TestValidateVersion(t *testing.T) {
	cases := map[string]string{
		"1.2.3":       "1.2.3",
		"v1.2.3":      "1.2.3",
		"v0.1.0-rc.1": "0.1.0-rc.1",
		"1.2.3+meta":  "1.2.3+meta",
	}
	for in, want := range cases {
		got, err := ValidateVersion(in)
		if err != nil || got != want {
			t.Errorf("ValidateVersion(%q) = (%q, %v), want (%q, nil)", in, got, err, want)
		}
	}
	invalid := []string{"", "абв", "1.2", "v", "1.2.3.4", "latest", "..", "01.2.3"}
	for _, in := range invalid {
		if _, err := ValidateVersion(in); err == nil {
			t.Errorf("ValidateVersion(%q) = nil error, want error", in)
		}
	}
}

func TestValidateFilename(t *testing.T) {
	valid := []string{"myapp-linux-amd64", "app v1.tar.gz", "a..b", strings.Repeat("a", 255)}
	for _, name := range valid {
		if err := ValidateFilename(name); err != nil {
			t.Errorf("ValidateFilename(%q) = %v, want nil", name, err)
		}
	}
	// Пробельные имена — в негодных, пробел внутри имени — в годных выше:
	// "   " это то же «пусто», а "app v1.tar.gz" — обычное имя (R7-test, 1).
	invalid := []string{"", "   ", "\t", " \n ", "a/../b", "a/b", `a\b`, ".", "..", "/etc/passwd", strings.Repeat("a", 256)}
	for _, name := range invalid {
		if err := ValidateFilename(name); err == nil {
			t.Errorf("ValidateFilename(%q) = nil, want error", name)
		}
	}
}

// TestValidateFilenameRejectsControlChars: управляющий символ в имени — отказ
// на входе, а не «invalid argument» из os.Link дальше по пути (R7-qa, 1).
// NUL здесь главный (ядро не принимает его в пути вовсе), но граница проведена
// по всей категории Cc, поэтому проверяются и края диапазонов C0/C1, и DEL.
func TestValidateFilenameRejectsControlChars(t *testing.T) {
	invalid := map[string]string{
		"a\x00b.tar.gz": "NUL — тот самый 500 из приёмки волны 7",
		"\x00":          "имя из одного NUL",
		"a\nb.tar.gz":   "перевод строки уезжает в Content-Disposition и в журнал",
		"a\rb.tar.gz":   "возврат каретки — та же болезнь",
		"a\x01b":        "нижний край C0",
		"a\x1fb":        "верхний край C0",
		"a\x7fb":        "DEL",
		"a\u0080b":      "нижний край C1",
		"a\u009fb":      "верхний край C1",
	}
	for name, why := range invalid {
		if err := ValidateFilename(name); err == nil {
			t.Errorf("ValidateFilename(%q) = nil, want error (%s)", name, why)
		}
	}
	// Граница снизу: непечатаемое отвергается, обычный не-ASCII — нет. Имена
	// вроде "приложение-1.0.0.tar.gz" законны и до правки принимались.
	valid := []string{"приложение-1.0.0.tar.gz", "app v1.tar.gz", "app–v1.tar.gz"}
	for _, name := range valid {
		if err := ValidateFilename(name); err != nil {
			t.Errorf("ValidateFilename(%q) = %v, want nil: правка не должна запрещать не-ASCII", name, err)
		}
	}
}

// TestNeighbourValidatorsRejectControlChars фиксирует, что соседние валидаторы
// той же дыры не имеют и чинить их не потребовалось: оба работают по белому
// списку (ValidateAppName — алфавит `[a-zA-Z0-9._-]`, ValidateVersion — строгий
// semver), а `$` в Go-регулярке — конец текста, а не конец строки, поэтому
// хвостовой "\n" не проскакивает. Тест держит это свойство, а не описывает его
// в отчёте: белый список легко расширить и не заметить, что вместе с новым
// символом впустил и управляющие (R7-qa, 1).
func TestNeighbourValidatorsRejectControlChars(t *testing.T) {
	for _, name := range []string{"app\x00", "app\n", "\napp", "app\x7f", "ap\x01p"} {
		if err := ValidateAppName(name); err == nil {
			t.Errorf("ValidateAppName(%q) = nil, want error", name)
		}
	}
	for _, v := range []string{"1.0.0\x00", "1.0.0\n", "\n1.0.0", "1.0.0\x7f", "1.0\x01.0"} {
		if canon, err := ValidateVersion(v); err == nil {
			t.Errorf("ValidateVersion(%q) = (%q, nil), want error", v, canon)
		}
	}
}

func TestNormalizeUsername(t *testing.T) {
	// Обрезка краёв — та же для всех трёх интерфейсов, иначе " ops " и "ops"
	// становятся двумя визуально одинаковыми учётками.
	trimmed := map[string]string{
		" ops ": "ops", "\tops\n": "ops", "ops": "ops",
		"ci-bot.v2": "ci-bot.v2", "a": "a", strings.Repeat("a", 64): strings.Repeat("a", 64),
	}
	for in, want := range trimmed {
		got, err := NormalizeUsername(in)
		if err != nil || got != want {
			t.Errorf("NormalizeUsername(%q) = (%q, %v), want (%q, nil)", in, got, err, want)
		}
	}
	invalid := []string{
		"", "   ", "ci:bot", // двоеточие — разделитель в HTTP Basic
		"a\nb", "a\x00b", // управляющие символы
		"admin ops", "-lead", ".hidden", // пробел внутри и небуквенный первый символ
		"оператор", "admın", // не-ASCII: гомоглифы и неоднозначная кодировка Basic
		strings.Repeat("a", 65),
	}
	for _, in := range invalid {
		if got, err := NormalizeUsername(in); err == nil {
			t.Errorf("NormalizeUsername(%q) = (%q, nil), want error", in, got)
		}
	}
}

// TestLegacyUsername: отбор учёток, которые из API и CLI по своему имени
// больше не адресуются. Один и тот же отбор питает предупреждение CLI и
// пометку на странице /users, поэтому проверяется здесь, а не у вызывающих.
func TestLegacyUsername(t *testing.T) {
	legacy := []string{
		"admin ", " admin", // нормализуется в чужое имя — операция уходит не на ту строку
		"аlice",  // кириллическая "а": визуальный двойник
		"ci:bot", // двоеточие ломает HTTP Basic
		"al ice", ".hidden", "", "   ",
	}
	for _, name := range legacy {
		if !LegacyUsername(name) {
			t.Errorf("LegacyUsername(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"alice", "ci-bot", "a.b_c-9", "admin", "0"} {
		if LegacyUsername(name) {
			t.Errorf("LegacyUsername(%q) = true, want false", name)
		}
	}
}

func TestValidatePassword(t *testing.T) {
	// Обе границы включительно: ровно MinPasswordBytes и ровно MaxPasswordBytes
	// принимаются — иначе off-by-one в политике заметит только пользователь.
	for _, pw := range []string{
		strings.Repeat("a", MinPasswordBytes), "s3cret-pass",
		strings.Repeat("a", MaxPasswordBytes),
	} {
		if err := ValidatePassword(pw); err != nil {
			t.Errorf("ValidatePassword(%d bytes) = %v, want nil", len(pw), err)
		}
	}
	// Снизу — минимум политики, сверху — предел bcrypt: он такой вход
	// отвергает, а не обрезает, поэтому это ошибка ввода (400), а не сбой (500).
	for _, pw := range []string{
		"", "x", strings.Repeat("a", MinPasswordBytes-1),
		strings.Repeat("a", MaxPasswordBytes+1), strings.Repeat("é", 40),
	} {
		if err := ValidatePassword(pw); err == nil {
			t.Errorf("ValidatePassword(%d bytes) = nil, want error", len(pw))
		}
	}
}
