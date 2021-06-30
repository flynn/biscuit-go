package biscuit

import (
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go/datalog"
	"github.com/stretchr/testify/require"
)

func TestFromDatalogFact(t *testing.T) {
	now := time.Now()

	symbolTable := &datalog.SymbolTable{"sym0", "sym1", "var1"}
	dlFact := datalog.Fact{
		Predicate: datalog.Predicate{
			Name: datalog.Symbol(0),
			IDs: []datalog.ID{
				datalog.Symbol(1),
				datalog.Integer(42),
				datalog.String("foo"),
				datalog.Variable(2),
				datalog.Date(now.Unix()),
				datalog.Bytes([]byte("some random bytes")),
				datalog.Bool(true),
				datalog.Bool(false),
				datalog.Set{
					datalog.String("abc"),
					datalog.Integer(42),
					datalog.Symbol(1),
				},
			},
		},
	}

	fact, err := fromDatalogFact(symbolTable, dlFact)
	require.NoError(t, err)

	expectedFact := &Fact{
		Predicate: Predicate{
			Name: "sym0",
			IDs: []Term{
				Symbol("sym1"),
				Integer(42),
				String("foo"),
				Variable("var1"),
				Date(time.Unix(now.Unix(), 0)),
				Bytes([]byte("some random bytes")),
				Bool(true),
				Bool(false),
				Set{String("abc"), Integer(42), Symbol("sym1")},
			},
		},
	}
	require.Equal(t, expectedFact, fact)
}
