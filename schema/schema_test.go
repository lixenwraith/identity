package schema

import (
	"strings"
	"testing"
)

func TestMigrationsAreNumberedWithoutAGap(t *testing.T) {
	list, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	if list[0].Version != 1 || list[0].Name != "init" {
		t.Fatalf("first migration is %03d_%s", list[0].Version, list[0].Name)
	}
	for i, m := range list {
		if m.Version != i+1 {
			t.Fatalf("migration %d has version %d", i+1, m.Version)
		}
		if !strings.Contains(m.SQL, "schema_version") {
			t.Errorf("%03d_%s.sql does not record its version", m.Version, m.Name)
		}
	}
}

func TestSetupIsNotAMigration(t *testing.T) {
	if _, err := Files.ReadFile("setup.sql"); err != nil {
		t.Fatal(err)
	}
	list, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range list {
		if strings.Contains(m.SQL, "CREATE ROLE") || strings.Contains(m.SQL, "CREATE DATABASE") {
			t.Fatalf("%03d_%s.sql provisions roles or databases; that is setup.sql's", m.Version, m.Name)
		}
	}
}
