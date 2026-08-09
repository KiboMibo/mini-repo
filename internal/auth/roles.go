package auth

import (
	"fmt"
	"net/http"
	"strings"
)

// Role — глобальная роль учётки, ровно одна на пользователя.
type Role string

const (
	RoleDeployer   Role = "deployer"
	RoleDeveloper  Role = "developer"
	RoleMaintainer Role = "maintainer"
	RoleAdmin      Role = "admin"
)

// Permission — право, которое проверяет Require.
type Permission int

const (
	PermRead      Permission = iota // скачивание и GET-запросы API
	PermVersion                     // залить/удалить версию
	PermApp                         // создать/переименовать/удалить приложение
	PermUserAdmin                   // управление пользователями
	PermUI                          // доступ в веб-интерфейс
)

// rolePerms — матрица прав битовой маской, по строке на роль. deployer —
// машинная учётка для CI и прямых ссылок: читать может, в UI не допускается.
var rolePerms = map[Role]uint{
	RoleDeployer:   bit(PermRead),
	RoleDeveloper:  bit(PermRead) | bit(PermVersion) | bit(PermUI),
	RoleMaintainer: bit(PermRead) | bit(PermVersion) | bit(PermApp) | bit(PermUI),
	RoleAdmin:      bit(PermRead) | bit(PermVersion) | bit(PermApp) | bit(PermUserAdmin) | bit(PermUI),
}

func bit(p Permission) uint { return 1 << uint(p) }

// AllRoles returns the roles in order of increasing privilege, for dropdowns
// and help text.
func AllRoles() []Role {
	return []Role{RoleDeployer, RoleDeveloper, RoleMaintainer, RoleAdmin}
}

// ParseRole accepts an exact role value; anything else — unknown names, other
// letter case, the empty string — is an error.
func ParseRole(s string) (Role, error) {
	for _, r := range AllRoles() {
		if string(r) == s {
			return r, nil
		}
	}
	names := make([]string, len(AllRoles()))
	for i, r := range AllRoles() {
		names[i] = string(r)
	}
	return "", fmt.Errorf("unknown role %q (want one of: %s)", s, strings.Join(names, ", "))
}

// Can reports whether the role grants p. An unknown role grants nothing, so a
// value that somehow bypassed ParseRole fails closed.
func (r Role) Can(p Permission) bool { return rolePerms[r]&bit(p) != 0 }

// Require is a middleware to be chained AFTER RequireBasic/RequireSession: the
// user already in the request context must hold p, otherwise 403.
//
// По умолчанию отказ — JSON в формате ошибок API (`{"error":"forbidden",…}`).
// Вызывающему с другим форматом (UI-страница) не нужно менять этот код: Auth
// без состояния, заведите второй экземпляр со своим обработчиком —
//
//	uiAuth := &auth.Auth{Store: a.Store, Forbidden: renderForbiddenPage}
func (a *Auth) Require(p Permission, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Пользователя в контексте нет, только если Require повесили без
		// RequireBasic/RequireSession впереди — это ошибка сборки маршрутов,
		// и безопасный ответ на неё тот же отказ.
		if u := a.CurrentUser(r); u == nil || !Role(u.Role).Can(p) {
			if a.Forbidden != nil {
				a.Forbidden(w, r)
				return
			}
			jsonError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		} else {
			next.ServeHTTP(w, r)
		}
	})
}
