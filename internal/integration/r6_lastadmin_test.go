package integration

// Защита последнего админа сквозь HTTP: последнего активного администратора
// нельзя разжаловать, заблокировать и удалить ни через API, ни через UI, а
// себя нельзя удалить вообще. Отдельно — гонка двух одновременных разжалований.

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"apprepo/internal/auth"
)

// enabledAdmins reads the invariant straight from the store: сколько админов
// реально могут войти. Ноль — это и есть та поломка, которую тест ловит.
func (e *env) enabledAdmins() int {
	e.t.Helper()
	n, err := e.st.CountAdmins()
	if err != nil {
		e.t.Fatalf("CountAdmins: %v", err)
	}
	return n
}

// TestLastAdminProtectedOverAPI: единственный админ не может разжаловать,
// заблокировать или удалить себя через JSON API.
func TestLastAdminProtectedOverAPI(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	if n := e.enabledAdmins(); n != 1 {
		t.Fatalf("подготовка: активных админов %d, want 1", n)
	}

	t.Run("нельзя_разжаловать", func(t *testing.T) {
		code, body := e.patchUser(adminCred, testUser, `{"role":"maintainer"}`)
		if code != http.StatusConflict || !strings.Contains(body, "last_admin") {
			t.Errorf("PATCH role: status = %d, body = %s; want 409 last_admin", code, body)
		}
		if got := e.mustStoreUser(testUser).Role; got != string(auth.RoleAdmin) {
			t.Errorf("роль изменилась на %q несмотря на отказ", got)
		}
	})

	t.Run("нельзя_заблокировать", func(t *testing.T) {
		code, body := e.patchUser(adminCred, testUser, `{"disabled":true}`)
		if code != http.StatusConflict || !strings.Contains(body, "last_admin") {
			t.Errorf("PATCH disabled: status = %d, body = %s; want 409 last_admin", code, body)
		}
		if e.mustStoreUser(testUser).Disabled {
			t.Error("учётка заблокирована несмотря на отказ")
		}
	})

	t.Run("нельзя_удалить_себя", func(t *testing.T) {
		code, body := e.statusAs(adminCred, "DELETE", "/api/users/"+testUser, nil, nil)
		if code != http.StatusConflict || !strings.Contains(body, "self_delete") {
			t.Errorf("DELETE себя: status = %d, body = %s; want 409 self_delete", code, body)
		}
		e.wantStatusAs(adminCred, "GET", "/api/me", nil, http.StatusOK, "учётка на месте")
	})

	t.Run("запрет_самоудаления_держится_и_при_втором_админе", func(t *testing.T) {
		// Второй админ снимает вопрос «последнего», но не вопрос «своей» учётки.
		e.mkUser("second-admin", "second-pass", string(auth.RoleAdmin))
		code, body := e.statusAs(adminCred, "DELETE", "/api/users/"+testUser, nil, nil)
		if code != http.StatusConflict || !strings.Contains(body, "self_delete") {
			t.Errorf("DELETE себя при двух админах: status = %d, body = %s; want 409 self_delete",
				code, body)
		}
	})

	t.Run("разжалование_разрешено_когда_админ_не_последний", func(t *testing.T) {
		code, body := e.patchUser(adminCred, testUser, `{"role":"maintainer"}`)
		if code != http.StatusOK {
			t.Fatalf("PATCH role при двух админах: status = %d, want 200; body: %s", code, body)
		}
		if n := e.enabledAdmins(); n != 1 {
			t.Errorf("активных админов = %d, want 1", n)
		}
		// И теперь оставшийся админ снова защищён.
		second := cred{"second-admin", "second-pass"}
		code, body = e.patchUser(second, "second-admin", `{"role":"developer"}`)
		if code != http.StatusConflict || !strings.Contains(body, "last_admin") {
			t.Errorf("разжалование нового последнего админа: status = %d, body = %s; want 409",
				code, body)
		}
		if n := e.enabledAdmins(); n != 1 {
			t.Errorf("система осталась с %d админами", n)
		}
	})
}

// TestLastAdminProtectedOverUI: те же три отказа через веб-интерфейс, с теми
// же последствиями для состояния.
func TestLastAdminProtectedOverUI(t *testing.T) {
	e := newEnv(t, defaultMaxUpload)
	c := e.mustLoginAs(adminCred)
	id := strconv.FormatInt(e.userID(testUser), 10)

	t.Run("нельзя_разжаловать", func(t *testing.T) {
		code, body := e.uiPostStatus(c, "/users/"+id+"/role", url.Values{"role": {"developer"}})
		if code != http.StatusConflict {
			t.Errorf("POST роли: status = %d, want 409; body: %s", code, body)
		}
		if !strings.Contains(body, "last administrator") {
			t.Errorf("страница не объясняет отказ; body: %s", body)
		}
		if got := e.mustStoreUser(testUser).Role; got != string(auth.RoleAdmin) {
			t.Errorf("роль изменилась на %q несмотря на отказ", got)
		}
	})

	t.Run("нельзя_заблокировать", func(t *testing.T) {
		code, body := e.uiPostStatus(c, "/users/"+id+"/disabled", url.Values{"disabled": {"true"}})
		if code != http.StatusConflict {
			t.Errorf("POST блокировки: status = %d, want 409; body: %s", code, body)
		}
		if e.mustStoreUser(testUser).Disabled {
			t.Error("учётка заблокирована несмотря на отказ")
		}
	})

	t.Run("нельзя_удалить_себя", func(t *testing.T) {
		code, body := e.uiPostStatus(c, "/users/"+id+"/delete", url.Values{"confirm": {testUser}})
		if code != http.StatusConflict {
			t.Errorf("POST удаления себя: status = %d, want 409; body: %s", code, body)
		}
		if !strings.Contains(body, "your own account") {
			t.Errorf("страница не объясняет отказ самоудаления; body: %s", body)
		}
		if n := e.enabledAdmins(); n != 1 {
			t.Errorf("активных админов = %d, want 1", n)
		}
	})

	t.Run("защита_держится_после_блокировки_второго_админа", func(t *testing.T) {
		// Заблокированный админ не считается активным: сразу после блокировки
		// оставшийся снова становится последним и снова защищён.
		e.mkUser("spare", "spare-pass", string(auth.RoleAdmin))
		spareID := strconv.FormatInt(e.userID("spare"), 10)
		if code, body := e.uiPostStatus(c, "/users/"+spareID+"/disabled",
			url.Values{"disabled": {"true"}}); code != http.StatusSeeOther {
			t.Fatalf("блокировка запасного админа: status = %d, want 303; body: %s", code, body)
		}
		if n := e.enabledAdmins(); n != 1 {
			t.Fatalf("активных админов после блокировки = %d, want 1", n)
		}
		code, body := e.uiPostStatus(c, "/users/"+id+"/role", url.Values{"role": {"developer"}})
		if code != http.StatusConflict {
			t.Errorf("разжалование при заблокированном втором админе: status = %d, want 409; body: %s",
				code, body)
		}
	})
}

// TestConcurrentDemotionKeepsAnAdmin: два последних админа одновременно
// разжалуют друг друга. Что бы ни выиграло гонку, в системе обязан остаться
// хотя бы один активный администратор — иначе установка становится
// неуправляемой без похода в CLI.
func TestConcurrentDemotionKeepsAnAdmin(t *testing.T) {
	const rounds = 5
	for i := 0; i < rounds; i++ {
		e := newEnv(t, defaultMaxUpload)
		bob := e.mkUser("bob", "bob-pass", string(auth.RoleAdmin))
		if n := e.enabledAdmins(); n != 2 {
			t.Fatalf("подготовка: активных админов %d, want 2", n)
		}

		// Каждый запрос аутентифицируется тем, кого второй запрос разжалует —
		// то самое встречное разжалование, где наивная проверка «админов
		// больше одного» оставила бы систему без админов.
		type result struct {
			code int
			body string
		}
		var wg sync.WaitGroup
		start := make(chan struct{})
		res := make([]result, 2)
		pairs := []struct {
			actor  cred
			target string
		}{
			{adminCred, "bob"},
			{bob, testUser},
		}
		for j, p := range pairs {
			wg.Add(1)
			go func(j int, actor cred, target string) {
				defer wg.Done()
				<-start
				code, body := e.patchUser(actor, target, `{"role":"developer"}`)
				res[j] = result{code, body}
			}(j, p.actor, p.target)
		}
		close(start)
		wg.Wait()

		if n := e.enabledAdmins(); n < 1 {
			t.Fatalf("раунд %d: система осталась без активных админов; ответы: %+v", i, res)
		}
		if res[0].code == http.StatusOK && res[1].code == http.StatusOK {
			t.Errorf("раунд %d: оба разжалования прошли (200/200) — защита не сработала", i)
		}
		// Проигравший обязан получить внятный отказ, а не 500.
		for j, r := range res {
			switch r.code {
			case http.StatusOK, http.StatusConflict, http.StatusForbidden, http.StatusUnauthorized:
			default:
				t.Errorf("раунд %d, запрос %d: status = %d — ожидались 200/409/403/401; body: %s",
					i, j, r.code, r.body)
			}
		}
	}
}
