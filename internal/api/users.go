package api

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	"apprepo/internal/auth"
	"apprepo/internal/naming"
	"apprepo/internal/store"
)

// userJSON — публичное представление учётки. Хеша пароля здесь нет и быть не
// может: наружу уходит только эта структура.
type userJSON struct {
	Username  string `json:"username"`
	Role      string `json:"role"`
	Disabled  bool   `json:"disabled"`
	CreatedAt string `json:"created_at"`
}

// storeTimeFmt — формат store.User.CreatedAt (UTC, как в SQLite).
const storeTimeFmt = "2006-01-02 15:04:05"

// userObj отдаёт created_at в RFC 3339, как объекты приложения и версии;
// нераспознанное значение отдаётся как есть, а не подменяется нулевой датой.
func userObj(u *store.User) userJSON {
	created := u.CreatedAt
	if t, err := time.ParseInLocation(storeTimeFmt, created, time.UTC); err == nil {
		created = t.Format(time.RFC3339)
	}
	return userJSON{Username: u.Username, Role: u.Role, Disabled: u.Disabled, CreatedAt: created}
}

// decodeJSON reads a bounded JSON body into v, writing the 400 itself on a
// malformed one. Пустое тело — не ошибка: поля проверяются ниже по коду.
// Единственная точка разбора JSON-тела в пакете — здесь же стоит рубеж
// notJSON (см. его комментарий), поэтому забыть его на маршруте нельзя.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if notJSON(w, r) {
		return false
	}
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody)).Decode(v)
	if err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "validation", "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

// hashPassword validates and hashes a new password, writing the error response
// itself. Ни пароль, ни хеш не попадают ни в ответ, ни в журнал.
func hashPassword(w http.ResponseWriter, r *http.Request, pw string) (string, bool) {
	if err := naming.ValidatePassword(pw); err != nil {
		writeErr(w, http.StatusBadRequest, "validation", err.Error())
		return "", false
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		internalErr(w, r, err)
		return "", false
	}
	return hash, true
}

// userWriteErr maps a failed write to the users table: ErrLastAdmin — это
// конфликт состояния (последний админ), а ErrNoUser — учётка, удалённая между
// нашим поиском и записью; ни то, ни другое не сбой.
func userWriteErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrLastAdmin):
		writeErr(w, http.StatusConflict, "last_admin",
			"the last enabled admin cannot be demoted, disabled or deleted")
	case errors.Is(err, store.ErrNoUser):
		writeErr(w, http.StatusNotFound, "not_found", "user not found")
	default:
		internalErr(w, r, err)
	}
}

// mustUser resolves {username} to a user or writes a 404 and returns nil.
// Имя из пути проходит ту же нормализацию, что и при создании: иначе учётку,
// заведённую как "ops", нельзя было бы найти по " ops ", а невалидное имя
// уходило бы в SQL. Невалидное — это 404, а не 400, как и у имени приложения:
// такой учётки не может существовать.
func (s *server) mustUser(w http.ResponseWriter, r *http.Request) *store.User {
	name, err := naming.NormalizeUsername(r.PathValue("username"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "user not found")
		return nil
	}
	u, err := s.st.GetUser(name)
	if err != nil {
		internalErr(w, r, err)
		return nil
	}
	if u == nil {
		writeErr(w, http.StatusNotFound, "not_found", "user not found")
		return nil
	}
	return u
}

// --- /api/users (PermUserAdmin) ---

func (s *server) listUsers(w http.ResponseWriter, r *http.Request) {
	us, err := s.st.ListUsers()
	if err != nil {
		internalErr(w, r, err)
		return
	}
	out := make([]userJSON, 0, len(us))
	for _, u := range us {
		out = append(out, userObj(u))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	name, err := naming.NormalizeUsername(in.Username)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "validation", err.Error())
		return
	}
	role, err := auth.ParseRole(in.Role)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "validation", err.Error())
		return
	}
	hash, ok := hashPassword(w, r, in.Password)
	if !ok {
		return
	}
	if err := s.st.CreateUser(name, hash, string(role)); err != nil {
		if errors.Is(err, store.ErrExists) {
			writeErr(w, http.StatusConflict, "already_exists", "user already exists")
			return
		}
		internalErr(w, r, err)
		return
	}
	u, err := s.st.GetUser(name)
	if err != nil || u == nil {
		if err == nil {
			err = errors.New("user disappeared right after creation")
		}
		internalErr(w, r, err)
		return
	}
	log.Printf("api: user %q created user %q with role %q", s.actor(r), u.Username, u.Role)
	writeJSON(w, http.StatusCreated, userObj(u))
}

// updateUser changes the role and/or the disabled flag. Оба поля
// необязательны: тело без них (или пустое) ничего не меняет.
func (s *server) updateUser(w http.ResponseWriter, r *http.Request) {
	u := s.mustUser(w, r)
	if u == nil {
		return
	}
	var in struct {
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Role != nil && *in.Role != u.Role {
		role, err := auth.ParseRole(*in.Role)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "validation", err.Error())
			return
		}
		if err := s.st.SetUserRole(u.ID, string(role)); err != nil {
			userWriteErr(w, r, err)
			return
		}
		log.Printf("api: user %q changed role of user %q from %q to %q",
			s.actor(r), u.Username, u.Role, role)
		u.Role = string(role)
	}
	if in.Disabled != nil && *in.Disabled != u.Disabled {
		if err := s.st.SetUserDisabled(u.ID, *in.Disabled); err != nil {
			userWriteErr(w, r, err)
			return
		}
		verb := "enabled"
		if *in.Disabled {
			verb = "disabled"
		}
		log.Printf("api: user %q %s user %q", s.actor(r), verb, u.Username)
		u.Disabled = *in.Disabled
	}
	writeJSON(w, http.StatusOK, userObj(u))
}

// setUserPassword is the admin reset; сессии пользователя гасит store.
func (s *server) setUserPassword(w http.ResponseWriter, r *http.Request) {
	u := s.mustUser(w, r)
	if u == nil {
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	hash, ok := hashPassword(w, r, in.Password)
	if !ok {
		return
	}
	if err := s.st.SetUserPassword(u.ID, hash); err != nil {
		userWriteErr(w, r, err)
		return
	}
	log.Printf("api: user %q reset password of user %q", s.actor(r), u.Username)
	w.WriteHeader(http.StatusNoContent)
}

// deleteUser removes another account. Себя удалить нельзя: админ, оставшийся
// без учётки, — это не то, что имеют в виду, нажимая «удалить».
func (s *server) deleteUser(w http.ResponseWriter, r *http.Request) {
	u := s.mustUser(w, r)
	if u == nil {
		return
	}
	if cur := s.auth.CurrentUser(r); cur != nil && cur.ID == u.ID {
		writeErr(w, http.StatusConflict, "self_delete",
			"you cannot delete your own account; ask another admin")
		return
	}
	if err := s.st.DeleteUser(u.ID); err != nil {
		userWriteErr(w, r, err)
		return
	}
	log.Printf("api: user %q deleted user %q", s.actor(r), u.Username)
	w.WriteHeader(http.StatusNoContent)
}

// --- /api/me (любая роль) ---

func (s *server) getMe(w http.ResponseWriter, r *http.Request) {
	u := s.auth.CurrentUser(r)
	if u == nil {
		internalErr(w, r, errors.New("no authenticated user in context"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": u.Username, "role": u.Role})
}

// changeMyPassword меняет пароль текущего пользователя. Доступно любой роли,
// в том числе deployer'у, которому веб-интерфейс закрыт.
func (s *server) changeMyPassword(w http.ResponseWriter, r *http.Request) {
	u := s.auth.CurrentUser(r)
	if u == nil {
		internalErr(w, r, errors.New("no authenticated user in context"))
		return
	}
	var in struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if !auth.CheckPassword(u.PasswordHash, in.Current) {
		// Отдельный код, а не "forbidden": иначе клиент не отличает «пароль
		// набран неверно» от «роли не хватает права» — вердикты разные, а
		// лечатся по-разному. HTTP-код остаётся 403.
		writeErr(w, http.StatusForbidden, "invalid_password", "current password is incorrect")
		return
	}
	hash, ok := hashPassword(w, r, in.New)
	if !ok {
		return
	}
	if err := s.st.SetUserPassword(u.ID, hash); err != nil {
		userWriteErr(w, r, err)
		return
	}
	log.Printf("api: user %q changed own password", u.Username)
	w.WriteHeader(http.StatusNoContent)
}
