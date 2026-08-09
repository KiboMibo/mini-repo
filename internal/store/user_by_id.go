package store

// GetUserByID returns (nil, nil) when the user does not exist.
//
// Добавлено задачей T4 отдельным файлом: сессия хранит только user_id, а
// контрактный GetUser ищет по username — session-middleware иначе не может
// положить пользователя в контекст. Аддитивно, сигнатуры контракта не меняет.
func (s *Store) GetUserByID(id int64) (*User, error) {
	return scanUser(s.db.QueryRow(
		`SELECT `+userCols+` FROM users WHERE id = ?`, id))
}
