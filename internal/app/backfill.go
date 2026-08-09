package app

import (
	"log"
	"time"

	"apprepo/internal/files"
	"apprepo/internal/platform"
	"apprepo/internal/store"
)

// backfillBudget — сколько времени старт готов потратить на разбор файлов.
// С бюджетом чтения в internal/platform один файл стоит миллисекунды, так что
// в норме сюда не упирается никто; потолок нужен там, где версий десятки тысяч
// или где часть файлов не опознаётся никогда (архив, машина вне словаря) и
// перечитывается на каждом рестарте. Старт не должен зависеть от содержимого
// data-dir (R8-sec S1): что не успели — доберём на следующем запуске или
// руками через PATCH. Синхронно, а не в фоне: после New платформы обязаны быть
// на месте, на это заложены и вызывающий код, и тесты обновления установки.
// Переменная, а не константа: тест подменяет бюджет, чтобы проверить рубеж.
var backfillBudget = 5 * time.Second

// backfillPlatforms fills in the platform of versions that do not have one yet
// by looking at the file on disk. Versions uploaded before T24 all start empty;
// so does everything whose format carries no platform (an archive), and those
// stay empty until somebody sets them by hand.
//
// Живёт здесь, а не в store, по слоям: store не знает ни про files, ни про
// data-dir, а здесь известны оба. Вызывается из New на каждом старте и
// повторный прогон безопасен — берутся только строки с пустой платформой, а
// определение по одному и тому же файлу даёт один и тот же ответ.
//
// Старт не роняет ничего: отсутствующий, битый или враждебный файл — это
// пропуск, а не ошибка запуска (platform.Detect читает только заголовок и
// гасит панику разборщика). В журнал уходит одна итоговая строка, а не строка
// на версию: на репозитории в тысячу версий второе — это тысяча строк в логе
// при каждом рестарте. Пустая БД не пишет ничего.
func backfillPlatforms(st *store.Store, fst *files.Storage) {
	var checked, set, skipped int
	var firstErr error
	fail := func(err error) {
		skipped++
		if firstErr == nil {
			firstErr = err
		}
	}

	apps, err := st.ListApps()
	if err != nil {
		log.Printf("app: platform backfill: list apps: %v", err)
		return
	}
	deadline := time.Now().Add(backfillBudget)
	var ranOut bool
	// Запрос на приложение, а не один общий: store отдаёт версии только по
	// приложению, и заводить ради старта отдельный join незачем — счёт
	// приложений в этой установке измеряется десятками.
apps:
	for _, a := range apps {
		versions, err := st.ListVersions(a.ID)
		if err != nil {
			fail(err)
			continue
		}
		for _, v := range versions {
			if v.Platform != "" {
				continue
			}
			if time.Now().After(deadline) {
				ranOut = true
				break apps
			}
			checked++
			p, err := platform.Detect(fst.Path(a.Name, v.Version, v.Filename))
			if err != nil {
				fail(err)
				continue
			}
			if p == "" { // формат без платформы (архив) — не ошибка
				skipped++
				continue
			}
			if err := st.SetVersionPlatform(v.ID, p); err != nil {
				fail(err)
				continue
			}
			set++
		}
	}

	if ranOut {
		log.Printf("app: platform backfill: stopped after %v, checked %d version(s), set %d, skipped %d"+
			" — the rest is left for the next start or for PATCH by hand",
			backfillBudget, checked, set, skipped)
		return
	}
	if checked == 0 {
		return
	}
	if firstErr != nil {
		log.Printf("app: platform backfill: checked %d version(s), set %d, skipped %d (first error: %v)",
			checked, set, skipped, firstErr)
		return
	}
	log.Printf("app: platform backfill: checked %d version(s), set %d, skipped %d",
		checked, set, skipped)
}
