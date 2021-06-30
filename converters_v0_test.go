package biscuit

import (
	"math/rand"
	"regexp"
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go/datalog"
	"github.com/biscuit-auth/biscuit-go/pb"
	"github.com/stretchr/testify/require"
)

func TestConstraintConvertDateComparisonV0(t *testing.T) {
	now := time.Now()
	testCases := []struct {
		Desc     string
		Input    *pb.ConstraintV0
		Expected datalog.Expression
	}{
		{
			Desc: "date comparison after",
			Input: &pb.ConstraintV0{
				Id:   1,
				Kind: pb.ConstraintV0_DATE,
				Date: &pb.DateConstraintV0{
					Kind:  pb.DateConstraintV0_AFTER,
					After: uint64(now.Unix()),
				},
			},
			Expected: datalog.Expression{
				datalog.Value{ID: datalog.Variable(1)},
				datalog.Value{ID: datalog.Date(now.Unix())},
				datalog.BinaryOp{BinaryOpFunc: datalog.GreaterOrEqual{}},
			},
		},
		{
			Desc: "date comparison before",
			Input: &pb.ConstraintV0{
				Id:   2,
				Kind: pb.ConstraintV0_DATE,
				Date: &pb.DateConstraintV0{
					Kind:   pb.DateConstraintV0_BEFORE,
					Before: uint64(123456789),
				},
			},
			Expected: datalog.Expression{
				datalog.Value{ID: datalog.Variable(2)},
				datalog.Value{ID: datalog.Date(123456789)},
				datalog.BinaryOp{BinaryOpFunc: datalog.LessOrEqual{}},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {

			got, err := protoConstraintToTokenExprV0(testCase.Input)
			require.NoError(t, err)

			require.Equal(t, testCase.Expected, got)
		})
	}
}

func TestConstraintConvertIntegerComparisonV0(t *testing.T) {
	n := rand.Int63()
	testCases := []struct {
		Desc     string
		Input    *pb.ConstraintV0
		Expected datalog.Expression
	}{
		{
			Desc: "int comparison equal",
			Input: &pb.ConstraintV0{
				Id:   1,
				Kind: pb.ConstraintV0_INT,
				Int: &pb.IntConstraintV0{
					Kind:  pb.IntConstraintV0_EQUAL,
					Equal: n,
				},
			},
			Expected: datalog.Expression{
				datalog.Value{ID: datalog.Variable(1)},
				datalog.Value{ID: datalog.Integer(n)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Equal{}},
			},
		},
		{
			Desc: "int comparison larger",
			Input: &pb.ConstraintV0{
				Id:   2,
				Kind: pb.ConstraintV0_INT,
				Int: &pb.IntConstraintV0{
					Kind:   pb.IntConstraintV0_LARGER,
					Larger: n,
				},
			},
			Expected: datalog.Expression{
				datalog.Value{ID: datalog.Variable(2)},
				datalog.Value{ID: datalog.Integer(n)},
				datalog.BinaryOp{BinaryOpFunc: datalog.GreaterThan{}},
			},
		},
		{
			Desc: "int comparison larger or equal",
			Input: &pb.ConstraintV0{
				Id:   3,
				Kind: pb.ConstraintV0_INT,
				Int: &pb.IntConstraintV0{
					Kind:          pb.IntConstraintV0_LARGER_OR_EQUAL,
					LargerOrEqual: n,
				},
			},
			Expected: datalog.Expression{
				datalog.Value{ID: datalog.Variable(3)},
				datalog.Value{ID: datalog.Integer(n)},
				datalog.BinaryOp{BinaryOpFunc: datalog.GreaterOrEqual{}},
			},
		},
		{
			Desc: "int comparison lower",
			Input: &pb.ConstraintV0{
				Id:   1,
				Kind: pb.ConstraintV0_INT,
				Int: &pb.IntConstraintV0{
					Kind:  pb.IntConstraintV0_LOWER,
					Lower: n,
				},
			},
			Expected: datalog.Expression{
				datalog.Value{ID: datalog.Variable(1)},
				datalog.Value{ID: datalog.Integer(n)},
				datalog.BinaryOp{BinaryOpFunc: datalog.LessThan{}},
			},
		},
		{
			Desc: "int comparison lower or equal",
			Input: &pb.ConstraintV0{
				Id:   1,
				Kind: pb.ConstraintV0_INT,
				Int: &pb.IntConstraintV0{
					Kind:         pb.IntConstraintV0_LOWER_OR_EQUAL,
					LowerOrEqual: n,
				},
			},
			Expected: datalog.Expression{
				datalog.Value{ID: datalog.Variable(1)},
				datalog.Value{ID: datalog.Integer(n)},
				datalog.BinaryOp{BinaryOpFunc: datalog.LessOrEqual{}},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			got, err := protoConstraintToTokenExprV0(testCase.Input)
			require.NoError(t, err)
			require.Equal(t, testCase.Expected, got)
		})
	}
}

func TestConstraintConvertIntegerInV0(t *testing.T) {
	n1 := rand.Int63()
	n2 := rand.Int63()
	n3 := rand.Int63()

	testCases := []struct {
		Desc     string
		Input    *pb.ConstraintV0
		Expected datalog.Expression
	}{
		{
			Desc: "int comparison in",
			Input: &pb.ConstraintV0{
				Id: 1,
				Int: &pb.IntConstraintV0{
					Kind:  pb.IntConstraintV0_IN,
					InSet: []int64{n1, n2, n3},
				},
			},
			Expected: datalog.Expression{
				datalog.Value{ID: datalog.Set{
					datalog.Integer(n1),
					datalog.Integer(n2),
					datalog.Integer(n3),
				}},
				datalog.Value{ID: datalog.Variable(1)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
			},
		},
		{
			Desc: "int comparison not in",
			Input: &pb.ConstraintV0{
				Id: 2,
				Int: &pb.IntConstraintV0{
					Kind:     pb.IntConstraintV0_NOT_IN,
					NotInSet: []int64{n1, n2, n3},
				},
			},
			Expected: datalog.Expression{
				datalog.Value{ID: datalog.Set{
					datalog.Integer(n1),
					datalog.Integer(n2),
					datalog.Integer(n3),
				}},
				datalog.Value{ID: datalog.Variable(2)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
				datalog.UnaryOp{UnaryOpFunc: datalog.Negate{}},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			got, err := protoConstraintToTokenExprV0(testCase.Input)
			require.NoError(t, err)
			require.Equal(t, testCase.Expected, got)
		})
	}
}

func TestConstraintConvertStringComparisonV0(t *testing.T) {
	testCases := []struct {
		Desc     string
		Input    *pb.ConstraintV0
		Expected datalog.Expression
	}{
		{
			Desc: "string comparison equal",
			Input: &pb.ConstraintV0{
				Id:   1,
				Kind: pb.ConstraintV0_STRING,
				Str: &pb.StringConstraintV0{
					Kind:  pb.StringConstraintV0_EQUAL,
					Equal: "abcd",
				},
			},
			Expected: datalog.Expression{
				datalog.Value{ID: datalog.Variable(1)},
				datalog.Value{ID: datalog.String("abcd")},
				datalog.BinaryOp{BinaryOpFunc: datalog.Equal{}},
			},
		},
		{
			Desc: "string comparison prefix",
			Input: &pb.ConstraintV0{
				Id:   2,
				Kind: pb.ConstraintV0_STRING,
				Str: &pb.StringConstraintV0{
					Kind:   pb.StringConstraintV0_PREFIX,
					Prefix: "abcd",
				},
			},
			Expected: datalog.Expression{
				datalog.Value{ID: datalog.Variable(2)},
				datalog.Value{ID: datalog.String("abcd")},
				datalog.BinaryOp{BinaryOpFunc: datalog.Prefix{}},
			},
		},
		{
			Desc: "string comparison suffix",
			Input: &pb.ConstraintV0{
				Id:   2,
				Kind: pb.ConstraintV0_STRING,
				Str: &pb.StringConstraintV0{
					Kind:   pb.StringConstraintV0_SUFFIX,
					Suffix: "abcd",
				},
			},
			Expected: datalog.Expression{
				datalog.Value{ID: datalog.Variable(2)},
				datalog.Value{ID: datalog.String("abcd")},
				datalog.BinaryOp{BinaryOpFunc: datalog.Suffix{}},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			got, err := protoConstraintToTokenExprV0(testCase.Input)
			require.NoError(t, err)
			require.Equal(t, testCase.Expected, got)
		})
	}
}

func TestConstraintConvertStringInV0(t *testing.T) {
	s1 := "abcd"
	s2 := "efgh"

	testCases := []struct {
		Desc     string
		Input    *pb.ConstraintV0
		Expected datalog.Expression
	}{
		{
			Desc: "string comparison in",
			Input: &pb.ConstraintV0{
				Id:   1,
				Kind: pb.ConstraintV0_STRING,
				Str: &pb.StringConstraintV0{
					Kind:  pb.StringConstraintV0_IN,
					InSet: []string{s1, s2},
				},
			},
			Expected: datalog.Expression{
				datalog.Value{ID: datalog.Set{datalog.String(s1), datalog.String(s2)}},
				datalog.Value{ID: datalog.Variable(1)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
			},
		},
		{
			Desc: "string comparison not in",
			Input: &pb.ConstraintV0{
				Id:   2,
				Kind: pb.ConstraintV0_STRING,
				Str: &pb.StringConstraintV0{
					Kind:     pb.StringConstraintV0_NOT_IN,
					NotInSet: []string{s1, s2},
				},
			},
			Expected: datalog.Expression{
				datalog.Value{ID: datalog.Set{datalog.String(s1), datalog.String(s2)}},
				datalog.Value{ID: datalog.Variable(2)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
				datalog.UnaryOp{UnaryOpFunc: datalog.Negate{}},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			got, err := protoConstraintToTokenExprV0(testCase.Input)
			require.NoError(t, err)
			require.Equal(t, testCase.Expected, got)
		})
	}
}

func TestConstraintConvertStringRegexpV0(t *testing.T) {
	re := regexp.MustCompile(`[a-z0-9_]+`)

	testCases := []struct {
		Desc     string
		Input    *pb.ConstraintV0
		Expected datalog.Expression
	}{
		{
			Desc: "string regexp",
			Input: &pb.ConstraintV0{
				Id:   1,
				Kind: pb.ConstraintV0_STRING,
				Str: &pb.StringConstraintV0{
					Kind:  pb.StringConstraintV0_REGEX,
					Regex: re.String(),
				},
			},

			Expected: datalog.Expression{
				datalog.Value{ID: datalog.Variable(1)},
				datalog.Value{ID: datalog.String(re.String())},
				datalog.BinaryOp{BinaryOpFunc: datalog.Regex{}},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			got, err := protoConstraintToTokenExprV0(testCase.Input)
			require.NoError(t, err)
			require.Equal(t, testCase.Expected, got)
		})
	}
}

func TestConstraintConvertBytesComparisonV0(t *testing.T) {
	b := make([]byte, 64)
	_, err := rand.Read(b)
	require.NoError(t, err)

	testCases := []struct {
		Desc     string
		Input    *pb.ConstraintV0
		Expected datalog.Expression
	}{
		{
			Desc: "bytes comparison equal",
			Input: &pb.ConstraintV0{
				Id:   1,
				Kind: pb.ConstraintV0_BYTES,
				Bytes: &pb.BytesConstraintV0{
					Kind:  pb.BytesConstraintV0_EQUAL,
					Equal: b,
				},
			},
			Expected: datalog.Expression{
				datalog.Value{ID: datalog.Variable(1)},
				datalog.Value{ID: datalog.Bytes(b)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Equal{}},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			got, err := protoConstraintToTokenExprV0(testCase.Input)
			require.NoError(t, err)
			require.Equal(t, testCase.Expected, got)
		})
	}
}

func TestConstraintConvertBytesInV0(t *testing.T) {
	b1 := make([]byte, 64)
	_, err := rand.Read(b1)
	require.NoError(t, err)

	b2 := make([]byte, 128)
	_, err = rand.Read(b2)
	require.NoError(t, err)

	testCases := []struct {
		Desc     string
		Input    *pb.ConstraintV0
		Expected datalog.Expression
	}{
		{
			Desc: "bytes in",
			Input: &pb.ConstraintV0{
				Id:   1,
				Kind: pb.ConstraintV0_BYTES,
				Bytes: &pb.BytesConstraintV0{
					Kind:  pb.BytesConstraintV0_IN,
					InSet: [][]byte{b1, b2},
				},
			},
			Expected: datalog.Expression{
				datalog.Value{ID: datalog.Set{datalog.Bytes(b1), datalog.Bytes(b2)}},
				datalog.Value{ID: datalog.Variable(1)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
			},
		},
		{
			Desc: "bytes not in",
			Input: &pb.ConstraintV0{
				Id:   2,
				Kind: pb.ConstraintV0_BYTES,
				Bytes: &pb.BytesConstraintV0{
					Kind:     pb.BytesConstraintV0_NOT_IN,
					NotInSet: [][]byte{b1, b2},
				},
			},
			Expected: datalog.Expression{
				datalog.Value{ID: datalog.Set{datalog.Bytes(b1), datalog.Bytes(b2)}},
				datalog.Value{ID: datalog.Variable(2)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
				datalog.UnaryOp{UnaryOpFunc: datalog.Negate{}},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			got, err := protoConstraintToTokenExprV0(testCase.Input)
			require.NoError(t, err)
			require.Equal(t, testCase.Expected, got)
		})
	}
}

func TestConstraintConvertSymbolInV0(t *testing.T) {
	s1 := rand.Uint64()
	s2 := rand.Uint64()
	s3 := rand.Uint64()

	testCases := []struct {
		Desc     string
		Input    *pb.ConstraintV0
		Expected datalog.Expression
	}{
		{
			Desc: "symbol in",
			Input: &pb.ConstraintV0{
				Id:   1,
				Kind: pb.ConstraintV0_SYMBOL,
				Symbol: &pb.SymbolConstraintV0{
					Kind:  pb.SymbolConstraintV0_IN,
					InSet: []uint64{s1, s2, s3},
				},
			},
			Expected: datalog.Expression{
				datalog.Value{ID: datalog.Set{datalog.Symbol(s1), datalog.Symbol(s2), datalog.Symbol(s3)}},
				datalog.Value{ID: datalog.Variable(1)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
			},
		},
		{
			Desc: "symbol not in",
			Input: &pb.ConstraintV0{
				Id:   1,
				Kind: pb.ConstraintV0_SYMBOL,
				Symbol: &pb.SymbolConstraintV0{
					Kind:     pb.SymbolConstraintV0_NOT_IN,
					NotInSet: []uint64{s1, s2, s3},
				},
			},
			Expected: datalog.Expression{
				datalog.Value{ID: datalog.Set{datalog.Symbol(s1), datalog.Symbol(s2), datalog.Symbol(s3)}},
				datalog.Value{ID: datalog.Variable(1)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
				datalog.UnaryOp{UnaryOpFunc: datalog.Negate{}},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			got, err := protoConstraintToTokenExprV0(testCase.Input)
			require.NoError(t, err)
			require.Equal(t, testCase.Expected, got)
		})
	}
}

func TestRuleConvertV0(t *testing.T) {
	now := time.Now()

	in := &pb.RuleV0{
		Head: &pb.PredicateV0{Name: 42, Ids: []*pb.IDV0{{Kind: pb.IDV0_INTEGER, Integer: 1}, {Kind: pb.IDV0_STR, Str: "id_1"}}},
		Body: []*pb.PredicateV0{
			{Name: 43, Ids: []*pb.IDV0{{Kind: pb.IDV0_SYMBOL, Symbol: 2}, {Kind: pb.IDV0_DATE, Date: uint64(now.Unix())}}},
			{Name: 44, Ids: []*pb.IDV0{{Kind: pb.IDV0_BYTES, Bytes: []byte("abcd")}}},
		},
		Constraints: []*pb.ConstraintV0{
			{Id: 9, Kind: pb.ConstraintV0_INT, Int: &pb.IntConstraintV0{Kind: pb.IntConstraintV0_EQUAL, Equal: 42}},
			{Id: 99, Kind: pb.ConstraintV0_STRING, Str: &pb.StringConstraintV0{Kind: pb.StringConstraintV0_PREFIX, Prefix: "abcd"}},
		},
	}

	expected := &datalog.Rule{
		Head: datalog.Predicate{
			Name: datalog.Symbol(42),
			IDs:  []datalog.ID{datalog.Integer(1), datalog.String("id_1")},
		},
		Body: []datalog.Predicate{
			{
				Name: datalog.Symbol(43),
				IDs:  []datalog.ID{datalog.Symbol(2), datalog.Date(now.Unix())},
			}, {
				Name: datalog.Symbol(44),
				IDs:  []datalog.ID{datalog.Bytes([]byte("abcd"))},
			},
		},
		Expressions: []datalog.Expression{
			{
				datalog.Value{ID: datalog.Variable(9)},
				datalog.Value{ID: datalog.Integer(42)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Equal{}},
			},
			{
				datalog.Value{ID: datalog.Variable(99)},
				datalog.Value{ID: datalog.String("abcd")},
				datalog.BinaryOp{BinaryOpFunc: datalog.Prefix{}},
			},
		},
	}

	out, err := protoRuleToTokenRuleV0(in)
	require.NoError(t, err)
	require.Equal(t, expected, out)
}

func TestFactConvertV0(t *testing.T) {
	now := time.Now()
	in := &pb.FactV0{Predicate: &pb.PredicateV0{
		Name: 42,
		Ids: []*pb.IDV0{
			{Kind: pb.IDV0_SYMBOL, Symbol: 1},
			{Kind: pb.IDV0_INTEGER, Integer: 2},
			{Kind: pb.IDV0_VARIABLE, Variable: 3},
			{Kind: pb.IDV0_BYTES, Bytes: []byte("bytes")},
			{Kind: pb.IDV0_STR, Str: "abcd"},
			{Kind: pb.IDV0_DATE, Date: uint64(now.Unix())},
		},
	}}
	expected := &datalog.Fact{Predicate: datalog.Predicate{
		Name: datalog.Symbol(42),
		IDs: []datalog.ID{
			datalog.Symbol(1),
			datalog.Integer(2),
			datalog.Variable(3),
			datalog.Bytes([]byte("bytes")),
			datalog.String("abcd"),
			datalog.Date(now.Unix()),
		},
	}}

	out, err := protoFactToTokenFactV0(in)
	require.NoError(t, err)
	require.Equal(t, expected, out)
}

func TestBlockConvertV0(t *testing.T) {
	predicate := datalog.Predicate{
		Name: datalog.Symbol(12),
		IDs:  []datalog.ID{datalog.String("abcd")},
	}

	pbPredicate := &pb.PredicateV0{
		Name: 12,
		Ids:  []*pb.IDV0{{Kind: pb.IDV0_STR, Str: "abcd"}},
	}
	pbPredicateV1 := &pb.PredicateV1{
		Name: 12,
		Ids:  []*pb.IDV1{{Content: &pb.IDV1_Str{Str: "abcd"}}},
	}

	rule := &datalog.Rule{
		Head: predicate,
		Body: []datalog.Predicate{predicate},
		Expressions: []datalog.Expression{
			{
				datalog.Value{ID: datalog.Variable(13)},
				datalog.Value{ID: datalog.Integer(1234)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Equal{}},
			},
		},
	}

	pbRule := &pb.RuleV0{
		Head: pbPredicate,
		Body: []*pb.PredicateV0{pbPredicate},
		Constraints: []*pb.ConstraintV0{
			{
				Id:   13,
				Kind: pb.ConstraintV0_INT,
				Int:  &pb.IntConstraintV0{Kind: pb.IntConstraintV0_EQUAL, Equal: 1234},
			},
		},
	}
	pbRuleV1 := &pb.RuleV1{
		Head: pbPredicateV1,
		Body: []*pb.PredicateV1{pbPredicateV1},
		Expressions: []*pb.ExpressionV1{
			{Ops: []*pb.Op{
				{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 13}}}},
				{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Integer{Integer: 1234}}}},
				{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Equal}}},
			}},
		},
	}

	in := &Block{
		index:   42,
		symbols: &datalog.SymbolTable{"a", "b", "c", "d"},
		facts:   &datalog.FactSet{datalog.Fact{Predicate: predicate}},
		rules:   []datalog.Rule{*rule},
		checks:  []datalog.Check{{Queries: []datalog.Rule{*rule}}},
		context: "context",
	}

	pbBlockV0 := &pb.Block{
		Index:   42,
		Symbols: []string{"a", "b", "c", "d"},
		FactsV0: []*pb.FactV0{
			{Predicate: pbPredicate},
		},
		RulesV0:   []*pb.RuleV0{pbRule},
		CaveatsV0: []*pb.CaveatV0{{Queries: []*pb.RuleV0{pbRule}}},
		Context:   "context",
	}

	expectedPbBlockV1 := &pb.Block{
		Index:   42,
		Symbols: []string{"a", "b", "c", "d"},
		FactsV1: []*pb.FactV1{
			{Predicate: pbPredicateV1},
		},
		RulesV1:  []*pb.RuleV1{pbRuleV1},
		ChecksV1: []*pb.CheckV1{{Queries: []*pb.RuleV1{pbRuleV1}}},
		Context:  "context",
	}

	pbBlock, err := tokenBlockToProtoBlock(in)
	require.NoError(t, err)
	require.Equal(t, expectedPbBlockV1, pbBlock)

	out, err := protoBlockToTokenBlock(pbBlockV0)
	require.NoError(t, err)
	require.Equal(t, in, out)

	pbBlockV0.Version = MaxSchemaVersion + 1
	_, err = protoBlockToTokenBlock(pbBlockV0)
	require.Error(t, err)
}
