package api_test

// Задача F12: нормализация и валидация имени учётки, предел длины пароля,
// отличимый код неверного current_password. Рубеж Content-Type, тоже заведённый
// в F12, переписан в F14 на строгий белый список — его тесты в api_f14_test.go.

import (
	"net/http"
	"strings"
	"testing"
)

// TestUsernameValidatedOnCreate: имя обрезается по краям, а негодное
// отвергается на входе — 400, а не мёртвая с рождения учётка.
func TestUsernameValidatedOnCreate(t *testing.T) {
	mux := newMux(t)
	jsonCT := map[string]string{"Content-Type": "application/json"}
	create := func(name string) int {
		return do(t, mux, "POST", "/api/users",
			`{"username":"`+name+`","password":"pw1234567","role":"developer"}`, jsonCT).Code
	}

	// Обрезка: " ops " ложится как "ops" и находится по каноническому имени.
	if code := create(" ops "); code != http.StatusCreated {
		t.Fatalf("create \" ops \": code = %d, want 201", code)
	}
	wantStatus(t, do(t, mux, "PATCH", "/api/users/ops", "", nil), http.StatusOK)
	// Повтор того же имени с другими пробелами — дубль, а не вторая учётка.
	if code := create("  ops"); code != http.StatusConflict {
		t.Errorf("create \"  ops\": code = %d, want 409 — завелась вторая учётка", code)
	}

	// Негодные имена: двоеточие ломает HTTP Basic, остальное — мусор.
	for _, bad := range []string{"ci:bot", "   ", "", "-lead", "with space", "оператор", strings.Repeat("a", 65)} {
		if code := create(bad); code != http.StatusBadRequest {
			t.Errorf("create %q: code = %d, want 400", bad, code)
		}
	}
}

// TestPasswordLengthLimit: bcrypt отвергает вход длиннее 72 байт ошибкой, а не
// обрезает его, — без проверки это был бы 500 на пользовательском вводе.
func TestPasswordLengthLimit(t *testing.T) {
	mux := newMux(t)
	jsonCT := map[string]string{"Content-Type": "application/json"}
	long := strings.Repeat("a", 73)

	wantErr(t, do(t, mux, "POST", "/api/users",
		`{"username":"longpw","password":"`+long+`","role":"developer"}`, jsonCT),
		http.StatusBadRequest, "validation")
	wantErr(t, do(t, mux, "POST", "/api/users/"+testUser+"/password",
		`{"password":"`+long+`"}`, jsonCT), http.StatusBadRequest, "validation")
	wantErr(t, do(t, mux, "POST", "/api/me/password",
		`{"current_password":"`+testPass+`","new_password":"`+long+`"}`, jsonCT),
		http.StatusBadRequest, "validation")

	// Ровно 72 байта — рабочий пароль, а не отказ на границе.
	wantStatus(t, do(t, mux, "POST", "/api/users",
		`{"username":"maxpw","password":"`+strings.Repeat("a", 72)+`","role":"developer"}`, jsonCT),
		http.StatusCreated)
}
