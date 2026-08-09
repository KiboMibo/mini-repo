module apprepo

go 1.24.7

require (
	github.com/Masterminds/semver/v3 v3.5.0
	github.com/ncruces/go-sqlite3 v0.29.0
	golang.org/x/crypto v0.41.0
	golang.org/x/term v0.34.0
)

require (
	github.com/ncruces/julianday v1.0.0 // indirect
	github.com/tetratelabs/wazero v1.9.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
)

// Mirror-replaces: песочница разработки выпускает наружу только github.com.
// В среде с нормальной сетью их можно удалить (см. арх-решение 2 в плане).
replace (
	golang.org/x/crypto => github.com/golang/crypto v0.41.0
	golang.org/x/sys => github.com/golang/sys v0.34.0
	golang.org/x/term => github.com/golang/term v0.34.0
	golang.org/x/text => github.com/golang/text v0.28.0
)
