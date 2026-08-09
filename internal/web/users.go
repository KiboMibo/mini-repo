package web

// Управление учётками (только PermUserAdmin) и смена собственного пароля
// (любая роль, допущенная в интерфейс). Маршруты навешаны в Register.

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"apprepo/internal/auth"
	"apprepo/internal/naming"
	"apprepo/internal/store"
)

// --- своя учётка ---

// changeOwnPassword verifies the current password and replaces it. The store
// drops every session of the user, so the browser is logged out anyway:
// отправляем на /login с объяснением, а не на страницу, с которой всё равно
// выбросит редиректом.
func (h *handlers) changeOwnPassword(w http.ResponseWriter, r *http.Request) {
	u := h.auth.CurrentUser(r)
	if u == nil {
		// RequireSession стоит на маршруте и всегда кладёт пользователя в
		// контекст; nil означает, что маршрут повесили мимо guard — это баг
		// сборки, а не ввод пользователя, и разыменовывать здесь нечего.
		h.serverError(w, errors.New("no authenticated user in context"))
		return
	}
	pw := r.PostFormValue("password")
	pwErr := naming.ValidatePassword(pw)
	switch {
	case !auth.CheckPassword(u.PasswordHash, r.PostFormValue("current")):
		h.renderIndex(w, r, http.StatusUnauthorized, "password",
			"the current password is incorrect — the password was not changed")
	case pwErr != nil:
		h.renderIndex(w, r, http.StatusBadRequest, "password", "the new "+pwErr.Error())
	case pw != r.PostFormValue("confirm"):
		h.renderIndex(w, r, http.StatusBadRequest, "password",
			"the new password and its repeat do not match")
	default:
		if !h.setPassword(w, r, u.ID, pw) {
			return
		}
		log.Printf("web: user %q changed own password", u.Username)
		h.toLogin(w, r)
	}
}

// setPassword hashes pw and stores it, reporting whether it succeeded; on
// failure the response has already been written. Пароль сюда приходит уже
// проверенным (naming.ValidatePassword), поэтому ошибка bcrypt здесь — сбой.
func (h *handlers) setPassword(w http.ResponseWriter, r *http.Request, id int64, pw string) bool {
	hash, err := auth.HashPassword(pw)
	if err == nil {
		err = h.st.SetUserPassword(id, hash)
	}
	if err != nil {
		h.userWriteErr(w, r, err, "change the password of")
		return false
	}
	return true
}

// toLogin expires the session cookie and sends the user to the login page with
// a notice: SetUserPassword has just deleted every session row of theirs, and a
// stale cookie would only produce a redirect without explanation.
func (h *handlers) toLogin(w http.ResponseWriter, r *http.Request) {
	h.auth.LogoutUser(w, r)
	http.Redirect(w, r, "/login?m=password-changed", http.StatusSeeOther)
}

// --- список пользователей ---

func (h *handlers) usersPage(w http.ResponseWriter, r *http.Request) {
	h.renderUsers(w, r, http.StatusOK, "", "")
}

func (h *handlers) renderUsers(w http.ResponseWriter, r *http.Request, status int, dialog, errMsg string) {
	users, err := h.st.ListUsers()
	if err != nil {
		h.serverError(w, err)
		return
	}
	v := h.baseView(w, r)
	v.Users, v.Roles = users, auth.AllRoles()
	v.Legacy, v.Broken = legacyNames(users)
	if errMsg != "" {
		v.Error, v.Dialog = errMsg, dialog
	}
	h.render(w, status, "users", v)
}

// legacyNames maps the id of every account whose name predates the validation
// of wave 6 to that name in quotes — раздельно: broken — имена с двоеточием,
// которые по Basic не входят вовсе, legacy — остальные, рабочие. Отбор —
// naming.LegacyUsername/BrokenBasicUsername, тот же, что у предупреждения в
// CLI. Две карты, а не одна с признаком: страница метит эти строки разными
// значками, и оператору важно видеть, что одна учётка сломана, а другая просто
// неудобна (R6-qa круг 2). Кавычки (strconv.Quote) существенны: без них
// "admin " в списке неотличим от "admin", то есть пометка теряет смысл
// (R6-sec, N2-б).
func legacyNames(users []*store.User) (legacy, broken map[int64]string) {
	legacy, broken = map[int64]string{}, map[int64]string{}
	for _, u := range users {
		switch {
		case !naming.LegacyUsername(u.Username):
		case naming.BrokenBasicUsername(u.Username):
			broken[u.ID] = strconv.Quote(u.Username)
		default:
			legacy[u.ID] = strconv.Quote(u.Username)
		}
	}
	return legacy, broken
}

// targetUser resolves {id} from the path; on failure it has already written
// the response and returns nil (как loadApp для приложений).
func (h *handlers) targetUser(w http.ResponseWriter, r *http.Request) *store.User {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return nil
	}
	u, err := h.st.GetUserByID(id)
	if err != nil {
		h.serverError(w, err)
		return nil
	}
	if u == nil {
		http.NotFound(w, r)
		return nil
	}
	return u
}

// userWriteErr answers a failed write to the users table. store.ErrLastAdmin —
// это отказ по правилу («не остаться без администратора»), а не сбой: 409 с
// человеческим текстом, не 500. store.ErrNoUser — учётку удалил другой админ
// между нашим targetUser и записью: это 404, как если бы её не было и в начале.
// Пара к api.userWriteErr — те же два состояния, те же коды.
func (h *handlers) userWriteErr(w http.ResponseWriter, r *http.Request, err error, action string) {
	switch {
	case errors.Is(err, store.ErrLastAdmin):
		h.renderUsers(w, r, http.StatusConflict, "", "cannot "+action+
			" the last administrator — give the admin role to another account first")
	case errors.Is(err, store.ErrNoUser):
		http.NotFound(w, r)
	default:
		h.serverError(w, err)
	}
}

// isSelf reports whether u is the logged-in user.
func (h *handlers) isSelf(r *http.Request, u *store.User) bool {
	me := h.auth.CurrentUser(r)
	return me != nil && me.ID == u.ID
}

// --- операции над учётками ---

func (h *handlers) createUser(w http.ResponseWriter, r *http.Request) {
	// naming.NormalizeUsername — та же обрезка и та же проверка, что в API и в
	// CLI: имя, заведённое здесь, обязано находиться оттуда и наоборот.
	name, nameErr := naming.NormalizeUsername(r.PostFormValue("username"))
	pw := r.PostFormValue("password")
	pwErr := naming.ValidatePassword(pw)
	role, roleErr := auth.ParseRole(r.PostFormValue("role"))
	switch {
	case nameErr != nil:
		h.renderUsers(w, r, http.StatusBadRequest, "new-user", nameErr.Error())
		return
	case pwErr != nil:
		h.renderUsers(w, r, http.StatusBadRequest, "new-user", pwErr.Error())
		return
	case roleErr != nil:
		h.renderUsers(w, r, http.StatusBadRequest, "new-user", roleErr.Error())
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		h.serverError(w, err)
		return
	}
	if err := h.st.CreateUser(name, hash, string(role)); err != nil {
		if errors.Is(err, store.ErrExists) {
			h.renderUsers(w, r, http.StatusConflict, "new-user",
				fmt.Sprintf("user %q already exists", name))
			return
		}
		h.serverError(w, err)
		return
	}
	log.Printf("web: user %q created user %q with role %s", h.actor(r), name, role)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (h *handlers) setUserRole(w http.ResponseWriter, r *http.Request) {
	u := h.targetUser(w, r)
	if u == nil {
		return
	}
	role, err := auth.ParseRole(r.PostFormValue("role"))
	if err != nil {
		h.renderUsers(w, r, http.StatusBadRequest, "", err.Error())
		return
	}
	if err := h.st.SetUserRole(u.ID, string(role)); err != nil {
		h.userWriteErr(w, r, err, "demote")
		return
	}
	log.Printf("web: user %q set role of %q to %s", h.actor(r), u.Username, role)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (h *handlers) setUserDisabled(w http.ResponseWriter, r *http.Request) {
	u := h.targetUser(w, r)
	if u == nil {
		return
	}
	disabled := r.PostFormValue("disabled") == "true"
	if err := h.st.SetUserDisabled(u.ID, disabled); err != nil {
		h.userWriteErr(w, r, err, "block")
		return
	}
	log.Printf("web: user %q set disabled=%t on %q", h.actor(r), disabled, u.Username)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// resetUserPassword is the admin-side reset: no current password is asked for.
func (h *handlers) resetUserPassword(w http.ResponseWriter, r *http.Request) {
	u := h.targetUser(w, r)
	if u == nil {
		return
	}
	pw := r.PostFormValue("password")
	if err := naming.ValidatePassword(pw); err != nil {
		h.renderUsers(w, r, http.StatusBadRequest, "", err.Error())
		return
	}
	if !h.setPassword(w, r, u.ID, pw) {
		return
	}
	log.Printf("web: user %q reset the password of %q", h.actor(r), u.Username)
	if h.isSelf(r, u) {
		h.toLogin(w, r) // сброс себе погасил и текущую сессию
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// deleteUser removes an account. Подтверждение вводом имени — как у удаления
// приложения: операция необратима и уносит с собой сессии.
func (h *handlers) deleteUser(w http.ResponseWriter, r *http.Request) {
	u := h.targetUser(w, r)
	if u == nil {
		return
	}
	// Самоудаление отсекаем до guardLastAdmin: единственному админу иначе
	// достался бы невнятный «последний администратор» вместо причины.
	if h.isSelf(r, u) {
		h.renderUsers(w, r, http.StatusConflict, "",
			"you cannot delete your own account — ask another administrator")
		return
	}
	if r.PostFormValue("confirm") != u.Username {
		h.renderUsers(w, r, http.StatusBadRequest, "",
			fmt.Sprintf("type %q exactly to confirm deletion — nothing was deleted", u.Username))
		return
	}
	if err := h.st.DeleteUser(u.ID); err != nil {
		h.userWriteErr(w, r, err, "delete")
		return
	}
	log.Printf("web: user %q deleted user %q", h.actor(r), u.Username)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}
