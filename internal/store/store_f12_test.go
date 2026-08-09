package store

// F12: запись в учётку, которой уже нет, — состояние, а не сбой.

import (
	"errors"
	"testing"
)

// TestWriteToDeletedUserIsErrNoUser: между тем, как хендлер нашёл учётку, и
// тем, как он её изменил, другой админ может её удалить. Раньше UPDATE, не
// затронувший ни одной строки, давал безымянную ошибку и 500; теперь это
// ErrNoUser, который вызывающие мапят в 404.
func TestWriteToDeletedUserIsErrNoUser(t *testing.T) {
	s, _ := openTemp(t)
	mustUser(t, s, "keeper", roleAdmin) // чтобы guardLastAdmin не сработал первым
	id := mustUser(t, s, "doomed", roleAdmin)

	if err := s.DeleteUser(id); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	for name, err := range map[string]error{
		"SetUserRole":     s.SetUserRole(id, "developer"),
		"SetUserPassword": s.SetUserPassword(id, "hash"),
		"SetUserDisabled": s.SetUserDisabled(id, true),
	} {
		if !errors.Is(err, ErrNoUser) {
			t.Errorf("%s по удалённой учётке = %v, want ErrNoUser", name, err)
		}
	}
	// Повторное удаление по-прежнему не ошибка (как DeleteApp).
	if err := s.DeleteUser(id); err != nil {
		t.Errorf("повторный DeleteUser = %v, want nil", err)
	}
}
