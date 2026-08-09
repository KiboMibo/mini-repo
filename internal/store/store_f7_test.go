package store

import "testing"

// F7/S4: имя приложения — имя каталога, на который потом натравливают
// os.RemoveAll, поэтому CreateApp валидирует его так же, как UpdateApp, и
// невалидное имя не может попасть в таблицу даже мимо хендлеров.
func TestCreateAppValidatesName(t *testing.T) {
	s, _ := openTemp(t)

	for _, bad := range []string{"", "..", "../x", "a/b", ".tmp", "latest", "a b"} {
		if _, err := s.CreateApp(bad, ""); err == nil {
			t.Errorf("CreateApp(%q): ожидалась ошибка валидации", bad)
		}
		if a, err := s.GetApp(bad); err != nil || a != nil {
			t.Errorf("CreateApp(%q) оставил строку в таблице (app=%v, err=%v)", bad, a, err)
		}
	}

	// Валидное имя по-прежнему создаётся.
	if _, err := s.CreateApp("apprepo.db", ""); err != nil {
		t.Errorf("CreateApp валидного имени: %v", err)
	}
}
