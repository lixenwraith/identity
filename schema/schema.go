// Package schema ships the SQL the database is provisioned and migrated with:
// setup.sql for the superuser, once, and the numbered migrations the store
// applies in order, embedded so a binary and the schema it expects travel
// together.
package schema

import (
	"embed"
	"fmt"
	"regexp"
	"slices"
	"strconv"
)

//go:embed *.sql
var Files embed.FS

// Migration is one numbered file; its SQL records its own version in
// schema_version, so psql and the store apply it the same way.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

var migrationName = regexp.MustCompile(`^(\d{3})_([a-z0-9_]+)\.sql$`)

// Migrations lists the numbered files in order and refuses a gap or a
// duplicate: version N applies only onto a database at version N-1.
func Migrations() ([]Migration, error) {
	entries, err := Files.ReadDir(".")
	if err != nil {
		return nil, err
	}
	var list []Migration
	for _, entry := range entries {
		m := migrationName.FindStringSubmatch(entry.Name())
		if m == nil {
			continue
		}
		sql, err := Files.ReadFile(entry.Name())
		if err != nil {
			return nil, err
		}
		version, _ := strconv.Atoi(m[1])
		list = append(list, Migration{Version: version, Name: m[2], SQL: string(sql)})
	}
	slices.SortFunc(list, func(a, b Migration) int { return a.Version - b.Version })
	for i, m := range list {
		if m.Version != i+1 {
			return nil, fmt.Errorf("schema: migration %03d_%s.sql follows version %d", m.Version, m.Name, i)
		}
		if len(m.SQL) == 0 {
			return nil, fmt.Errorf("schema: migration %03d_%s.sql is empty", m.Version, m.Name)
		}
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("schema: no migration is embedded")
	}
	return list, nil
}
