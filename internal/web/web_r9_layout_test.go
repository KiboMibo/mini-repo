package web_test

// R9-test: вёрстка шапки держится на согласованных числах в layout.html, и
// комментарии рядом с правилами объясняют связь, но не стерегут её.
//
// Механизм (после F24): стрелка «назад» лежит ВНЕ ПОТОКА в поле слева, место под
// неё держит padding контейнера, а заголовок и первая колонка таблицы встают на
// один левый край.
//
//	.page-head{position:relative;margin-left:-X;padding-left:X}
//	.back{position:absolute;left:0;width:W}   где W <= X
//	main{padding: 0 R 0 R+X}                  левое поле шире правого на вылет X
//
// Первая редакция теста (круг 1) проверяла прежний механизм — «стрелка отыгрывает
// отступ своим местом в потоке», то есть равенство X = .back{width} +
// .page-head{gap}. После F24 эта формула ещё выполняется численно, но описывает
// не реальность: стрелка вне потока, и gap отделяет заголовок от соседей по
// флексу, а не от стрелки. Load-bearing число теперь padding-left, и старая
// редакция его не смотрела вовсе — удаление padding-left (ровно тот дефект,
// который F24 и чинил) оставляло тест зелёным. Переписано под новый механизм;
// конкретных значений тест по-прежнему не диктует, только их согласованность.

import (
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// rem вытаскивает число из значения вида "1.6rem" / "-1.6rem" / ".8rem".
func rem(t *testing.T, where, value string) float64 {
	t.Helper()
	v, err := strconv.ParseFloat(value, 64)
	if err != nil {
		t.Fatalf("%s: не разобрать %q как rem: %v", where, value, err)
	}
	return v
}

// declOf возвращает тело правила для селектора: layout.html держит весь CSS
// одной строкой на правило, поэтому этого достаточно.
func declOf(t *testing.T, css, selector string) string {
	t.Helper()
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(selector) + `\{([^}]*)\}`)
	m := re.FindStringSubmatch(css)
	if m == nil {
		t.Fatalf("в layout.html нет правила %s{…}", selector)
	}
	return m[1]
}

// propOf достаёт значение свойства из тела правила.
func propOf(t *testing.T, decl, prop string) string {
	t.Helper()
	re := regexp.MustCompile(`(?:^|;)\s*` + regexp.QuoteMeta(prop) + `:\s*([^;]+)`)
	m := re.FindStringSubmatch(decl)
	if m == nil {
		t.Fatalf("в правиле {%s} нет свойства %s", decl, prop)
	}
	return m[1]
}

func layoutCSS(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("templates/layout.html")
	if err != nil {
		t.Fatalf("read layout.html: %v", err)
	}
	return string(b)
}

// remProp читает свойство правила как значение в rem.
func remProp(t *testing.T, css, selector, prop string) float64 {
	t.Helper()
	raw := propOf(t, declOf(t, css, selector), prop)
	m := regexp.MustCompile(`^(-?[\d.]+)rem$`).FindStringSubmatch(raw)
	if m == nil {
		t.Fatalf("%s{%s} = %q: ожидалось значение в rem", selector, prop, raw)
	}
	return rem(t, selector+"{"+prop+"}", m[1])
}

// TestBackArrowOffsetsAgree: заголовок встаёт ровно на левый край таблицы, а
// стрелка помещается в отведённое ей поле и не обрезается краем main.
func TestBackArrowOffsetsAgree(t *testing.T) {
	css := layoutCSS(t)

	// Механизм: без position:relative у контейнера absolute-стрелка считает
	// left:0 от другого предка и уезжает; без position:absolute она возвращается
	// в поток, и padding контейнера начинает отсчитываться повторно.
	if got := propOf(t, declOf(t, css, ".page-head"), "position"); got != "relative" {
		t.Errorf(".page-head{position} = %q, want relative", got)
	}
	if got := propOf(t, declOf(t, css, ".back"), "position"); got != "absolute" {
		t.Errorf(".back{position} = %q, want absolute", got)
	}
	if got := propOf(t, declOf(t, css, ".back"), "left"); got != "0" {
		t.Errorf(".back{left} = %q, want 0", got)
	}

	shift := remProp(t, css, ".page-head", "margin-left")
	pad := remProp(t, css, ".page-head", "padding-left")
	width := remProp(t, css, ".back", "width")

	// Заголовок: контейнер выехал влево на |shift| и вернул содержимое обратно
	// padding'ом. Разойдясь, эти два числа сдвигают заголовок относительно
	// первой колонки таблицы — тот самый дефект, что чинил F24.
	if pad != -shift {
		t.Errorf(".page-head{padding-left} = %grem, а {margin-left} = %grem: "+
			"padding обязан возвращать содержимое ровно на сдвиг контейнера, "+
			"иначе заголовок разъезжается с первой колонкой таблицы", pad, shift)
	}
	// Стрелка лежит в освобождённом поле: шире поля — налезет на заголовок.
	if width > pad {
		t.Errorf(".back{width} = %grem шире поля .page-head{padding-left} = %grem: "+
			"стрелка налезет на заголовок", width, pad)
	}

	// main{padding: top right bottom left} — левое поле шире правого не меньше
	// чем на вылет стрелки, иначе она обрезается краем страницы.
	mainPad := propOf(t, declOf(t, css, "main"), "padding")
	m := regexp.MustCompile(`^0\s+(-?[\d.]+)rem\s+0\s+(-?[\d.]+)rem$`).FindStringSubmatch(mainPad)
	if m == nil {
		t.Fatalf("main{padding} = %q: ожидалось `0 <right> 0 <left>`", mainPad)
	}
	right, left := rem(t, "main{padding-right}", m[1]), rem(t, "main{padding-left}", m[2])
	if want := right - shift; left < want {
		t.Errorf("main{padding-left} = %grem < %grem (правое поле %grem + вылет "+
			"стрелки %grem): стрелка обрежется краем страницы", left, want, right, -shift)
	}

	// Первая колонка таблицы без левого отступа — иначе её текст не совпадёт с
	// заголовком, ради чего весь сдвиг и затевался.
	if got := propOf(t, declOf(t, css, "th:first-child,td:first-child"), "padding-left"); got != "0" {
		t.Errorf("th:first-child,td:first-child{padding-left} = %q, want 0", got)
	}

	// Длинное имя приложения без разделителей обязано переноситься, а не
	// вылезать за край страницы (F24, замер на имени в 64 символа).
	if got := propOf(t, declOf(t, css, ".page-head h1"), "overflow-wrap"); got != "anywhere" {
		t.Errorf(".page-head h1{overflow-wrap} = %q, want anywhere", got)
	}
}

// h1FontSizeRem — размер шрифта h1. В CSS страницы он не задан, это умолчание
// браузера (2em от body, у которого 1rem). Как только .page-head h1 обзаведётся
// своим font-size, тест об этом скажет — см. проверку ниже.
const h1FontSizeRem = 2.0

// TestBackArrowBaselineAndTapTarget: стрелка совпадает с первой строкой
// заголовка по вертикали, а нажать по ней можно пальцем.
func TestBackArrowBaselineAndTapTarget(t *testing.T) {
	css := layoutCSS(t)

	h1 := declOf(t, css, ".page-head h1")
	if strings.Contains(h1, "font-size") {
		t.Fatalf(".page-head h1 обзавёлся своим font-size — поправь h1FontSizeRem "+
			"в тесте, высота строки стрелки считается от него; правило: {%s}", h1)
	}
	lh := propOf(t, h1, "line-height")
	factor, err := strconv.ParseFloat(lh, 64)
	if err != nil {
		t.Fatalf(".page-head h1{line-height} = %q: ожидался множитель без единиц", lh)
	}

	// Стрелка центрируется по первой строке заголовка своим line-height —
	// подгонки top в CSS нет, поэтому числа обязаны сойтись.
	if got, want := remProp(t, css, ".back", "line-height"), factor*h1FontSizeRem; got != want {
		t.Errorf(".back{line-height} = %grem, want %grem (h1 line-height %g × "+
			"font-size %grem): глиф не совпадёт с первой строкой заголовка",
			got, want, factor, h1FontSizeRem)
	}

	// Зона нажатия расширена псевдоэлементом. WCAG 2.2 §2.5.8 (уровень AA) —
	// минимум 24×24 CSS-пикселя; при корневом шрифте 16px это 1.5rem.
	const minTargetRem = 1.5
	inset := remProp(t, css, ".back::before", "inset")
	if inset >= 0 {
		t.Errorf(".back::before{inset} = %grem: чтобы расширять зону нажатия, "+
			"значение обязано быть отрицательным", inset)
	}
	if w := remProp(t, css, ".back", "width") - 2*inset; w < minTargetRem {
		t.Errorf("зона нажатия стрелки %grem (ширина %grem + inset %grem с двух "+
			"сторон) уже минимума %grem из WCAG 2.2 §2.5.8",
			w, remProp(t, css, ".back", "width"), inset, minTargetRem)
	}
	if got := propOf(t, declOf(t, css, ".back::before"), "position"); got != "absolute" {
		t.Errorf(".back::before{position} = %q, want absolute (иначе inset ничего "+
			"не делает и зона нажатия не расширяется)", got)
	}
}

// evalRem вычисляет ширину в rem на экране шириной viewport rem. Понимает ровно
// те формы, которые встречаются в layout.html: "20rem", "calc(100vw - 2rem)" и
// min(…) от них. Нужна, чтобы тест проверял РЕЗУЛЬТАТ, а не форму записи: иначе
// он падал бы и на верном исправлении дефекта, то есть диктовал бы, каким
// именно выражением его чинить.
func evalRem(t *testing.T, where, expr string, viewport float64) float64 {
	t.Helper()
	expr = strings.TrimSpace(expr)
	switch {
	case strings.HasPrefix(expr, "min(") && strings.HasSuffix(expr, ")"):
		v := math.Inf(1)
		for _, arg := range splitTopLevel(expr[len("min(") : len(expr)-1]) {
			v = math.Min(v, evalRem(t, where, arg, viewport))
		}
		return v
	case strings.HasPrefix(expr, "calc(") && strings.HasSuffix(expr, ")"):
		m := regexp.MustCompile(`^100vw\s*-\s*([\d.]+)rem$`).
			FindStringSubmatch(strings.TrimSpace(expr[len("calc(") : len(expr)-1]))
		if m == nil {
			t.Fatalf("%s = %q: из calc() поддерживается только `100vw - <N>rem`", where, expr)
		}
		return viewport - rem(t, where, m[1])
	}
	m := regexp.MustCompile(`^([\d.]+)rem$`).FindStringSubmatch(expr)
	if m == nil {
		t.Fatalf("%s = %q: ожидалось значение в rem, calc() или min()", where, expr)
	}
	return rem(t, where, m[1])
}

// splitTopLevel режет список аргументов по запятым верхнего уровня — вложенный
// calc(a - b) запятых не содержит, но скобки считать всё равно надо.
func splitTopLevel(s string) []string {
	var out []string
	depth, start := 0, 0
	for i, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

// TestDialogFitsNarrowViewport: модалка не должна вылезать за узкий экран.
// max-width поле у краёв закладывает, но по CSS 2.1 §10.4 min-width сильнее
// max-width — значит и нижняя граница обязана считаться от ширины экрана.
// Самый узкий, на который рассчитывают, — 320 CSS-пикселей (20rem, iPhone SE);
// столько же даёт двукратный зум на окне в 640px.
func TestDialogFitsNarrowViewport(t *testing.T) {
	const narrowRem = 20.0 // 320px при корневом шрифте 16px

	dialog := declOf(t, layoutCSS(t), "dialog")

	// box-sizing обязателен: без него padding прибавляется к max-width.
	if got := propOf(t, dialog, "box-sizing"); got != "border-box" {
		t.Errorf("dialog{box-sizing} = %q, want border-box", got)
	}

	minRaw, maxRaw := propOf(t, dialog, "min-width"), propOf(t, dialog, "max-width")
	min := evalRem(t, "dialog{min-width}", minRaw, narrowRem)
	max := evalRem(t, "dialog{max-width}", maxRaw, narrowRem)

	if min > max {
		t.Errorf("на экране %grem: dialog{min-width}=%q даёт %grem, а "+
			"dialog{max-width}=%q — только %grem. min-width сильнее max-width, "+
			"поэтому поля у краёв не остаётся, а на экране уже %grem модалка "+
			"вылезает за край. Чинится тем же приёмом, что и max-width: "+
			"min-width:min(%s,calc(100vw - %grem))",
			narrowRem, minRaw, min, maxRaw, max, narrowRem, minRaw, narrowRem-max)
	}
	// Верхняя граница на месте: длинный текст подсказки не растягивает модалку.
	// Признак потолка — ширина перестаёт расти вместе с экраном.
	if a, b := evalRem(t, "dialog{max-width}", maxRaw, 120),
		evalRem(t, "dialog{max-width}", maxRaw, 240); a != b {
		t.Errorf("dialog{max-width}=%q растёт вместе с экраном (%grem на 120rem, "+
			"%grem на 240rem): потолка нет, длинный текст растянет модалку", maxRaw, a, b)
	}
}
