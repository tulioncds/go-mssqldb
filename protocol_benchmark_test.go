//go:build np
// +build np

package mssql

import (
	"database/sql"
	"testing"
)

// Compare TCP to Named Pipe
func BenchmarkNamedPipeProtocol(b *testing.B) {
	tl := testLogger{t: b}
	defer tl.StopLogging()
	SetLogger(&tl)
	b.Run("tcp", func(b *testing.B) { simpleConnectAndQuery(b, "tcp") })
	b.Run("np", func(b *testing.B) { simpleConnectAndQuery(b, "np") })
}

func simpleConnectAndQuery(b *testing.B, protocol string) {
	conn := testConnParams(b)
	conn.Protocols = []string{protocol}
	connStr := conn.URL().String()

	for i := 0; i < b.N; i++ {

		db, err := sql.Open("sqlserver", connStr)
		if err != nil {
			b.Fatalf("Unable to Open <%s>. %s", connStr, err.Error())
		}
		defer db.Close()
		db.SetMaxIdleConns(1)
		db.SetMaxOpenConns(1)

		rows := db.QueryRow("select 1")
		v := 0
		err = rows.Scan(&v)
		if err != nil {
			b.Fatalf("Unable to Scan. %s", err.Error())
		}

	}
}
