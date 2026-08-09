package web_test

// F16 (R6-qa круг 2): пометка на /users обязана различать два случая. Имя с
// пробелом или не-ASCII — учётка рабочая, ей мешает только адресация по имени;
// имя с двоеточием по Basic не входит вовсе (заголовок кодирует
// user:password), и оператор должен видеть, что эта учётка сломана.

import (
	"net/http"
	"strings"
	"testing"
)

func TestUsersPageMarksColonNameAsBroken(t *testing.T) {
	e := newEnv(t)
	broken := e.addRawUser(t, "ci:bot")
	spaced := e.addRawUser(t, "admin ")

	rec := e.do(t, "GET", "/users", "", nil, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /users = %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	brokenRow, spacedRow := userRow(t, body, broken), userRow(t, body, spaced)
	if !strings.Contains(brokenRow, `broken name &#34;ci:bot&#34;`) {
		t.Errorf("учётка с двоеточием не помечена как сломанная; row: %s", brokenRow)
	}
	if !strings.Contains(spacedRow, `legacy name &#34;admin &#34;`) {
		t.Errorf("учётка с пробелом потеряла пометку; row: %s", spacedRow)
	}
	// Главное: пометки различаются — иначе сломанная учётка выглядит как
	// просто неудобная.
	if strings.Contains(brokenRow, "legacy name") || strings.Contains(spacedRow, "broken name") {
		t.Errorf("пометки не различаются:\nдвоеточие: %s\nпробел: %s", brokenRow, spacedRow)
	}
	// Пояснение над таблицей объясняет, почему Basic отказывает.
	if !strings.Contains(body, "cannot sign in over Basic at all") {
		t.Errorf("на странице нет пояснения про отказ Basic; body: %s", body)
	}
}

// Без имён с двоеточием фраза про Basic не показывается: она про сломанную
// учётку, а рабочему старому имени приписывать отказ нельзя.
func TestUsersPageWithoutColonNamesKeepsWorkingWording(t *testing.T) {
	e := newEnv(t)
	e.addRawUser(t, "admin ")
	body := e.do(t, "GET", "/users", "", nil, true).Body.String()
	if !strings.Contains(body, "still works and can sign in") {
		t.Errorf("страница не говорит, что учётка со старым именем работает; body: %s", body)
	}
	if strings.Contains(body, "broken name") || strings.Contains(body, "cannot sign in over Basic") {
		t.Errorf("страница без имён с двоеточием пугает отказом Basic; body: %s", body)
	}
}
