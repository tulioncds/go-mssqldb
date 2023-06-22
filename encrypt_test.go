package mssql

import (
	"database/sql"
	"testing"
)

func TestSprocQueryForCE(t *testing.T) {
	type test struct {
		name     string
		proc     string
		args     []namedValue
		expected string
	}
	var out int
	tests := []test{
		{
			"Empty args",
			"m]yproc",
			make([]namedValue, 0),
			"EXEC [m]]yproc]",
		},
		{
			"No OUT args",
			"myproc",
			[]namedValue{
				{
					"p1",
					0,
					5,
				},
				{
					"@p2",
					0,
					"val",
				},
			},
			"EXEC [myproc] @p1=@p1, @p2=@p2",
		},
		{
			"OUT args",
			"myproc",
			[]namedValue{
				{
					"pout",
					0,
					sql.Out{
						Dest: &out,
						In:   false,
					},
				},
				{
					"pin",
					1,
					"in",
				},
			},
			"EXEC [myproc] @pout=@pout OUTPUT, @pin=@pin",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := buildStoredProcedureStatementForColumnEncryption(tc.proc, tc.args)
			if q != tc.expected {
				t.Fatalf("Incorrect query for %s: %s", tc.name, q)
			}
		})
	}
}
