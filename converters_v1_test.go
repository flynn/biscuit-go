package biscuit

import (
	"math"
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go/datalog"
	"github.com/biscuit-auth/biscuit-go/pb"
	"github.com/stretchr/testify/require"
)

func TestExpressionConvertV1(t *testing.T) {
	now := time.Now()

	testCases := []struct {
		Desc     string
		Input    datalog.Expression
		Expected *pb.ExpressionV1
	}{
		{
			Desc: "date comparison after",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(1)},
				datalog.Value{ID: datalog.Date(now.Unix())},
				datalog.BinaryOp{BinaryOpFunc: datalog.GreaterOrEqual{}},
			},
			Expected: &pb.ExpressionV1{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 1}}}},
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Date{Date: uint64(now.Unix())}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_GreaterOrEqual}}},
				},
			},
		},
		{
			Desc: "date comparison before",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(2)},
				datalog.Value{ID: datalog.Date(123456789)},
				datalog.BinaryOp{BinaryOpFunc: datalog.LessOrEqual{}},
			},
			Expected: &pb.ExpressionV1{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 2}}}},
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Date{Date: uint64(123456789)}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_LessOrEqual}}},
				},
			},
		},
		{
			Desc: "int comparison equal",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(3)},
				datalog.Value{ID: datalog.Integer(42)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Equal{}},
			},
			Expected: &pb.ExpressionV1{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 3}}}},
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Integer{Integer: 42}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Equal}}},
				},
			},
		},
		{
			Desc: "int comparison larger",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(4)},
				datalog.Value{ID: datalog.Integer(-42)},
				datalog.BinaryOp{BinaryOpFunc: datalog.GreaterThan{}},
			},
			Expected: &pb.ExpressionV1{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 4}}}},
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Integer{Integer: -42}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_GreaterThan}}},
				},
			},
		},
		{
			Desc: "int comparison larger or equal",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(5)},
				datalog.Value{ID: datalog.Integer(43)},
				datalog.BinaryOp{BinaryOpFunc: datalog.GreaterOrEqual{}},
			},
			Expected: &pb.ExpressionV1{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 5}}}},
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Integer{Integer: 43}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_GreaterOrEqual}}},
				},
			},
		},
		{
			Desc: "int comparison lower",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(6)},
				datalog.Value{ID: datalog.Integer(0)},
				datalog.BinaryOp{BinaryOpFunc: datalog.LessThan{}},
			},
			Expected: &pb.ExpressionV1{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 6}}}},
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Integer{Integer: 0}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_LessThan}}},
				},
			},
		},
		{
			Desc: "int comparison lower or equal",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(7)},
				datalog.Value{ID: datalog.Integer(math.MaxInt64)},
				datalog.BinaryOp{BinaryOpFunc: datalog.LessOrEqual{}},
			},
			Expected: &pb.ExpressionV1{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 7}}}},
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Integer{Integer: math.MaxInt64}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_LessOrEqual}}},
				},
			},
		},
		{
			Desc: "int comparison in",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Set{datalog.Integer(1), datalog.Integer(2), datalog.Integer(3)}},
				datalog.Value{ID: datalog.Variable(8)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
			},
			Expected: &pb.ExpressionV1{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Set{Set: &pb.IDSet{Set: []*pb.IDV1{
						{Content: &pb.IDV1_Integer{Integer: 1}},
						{Content: &pb.IDV1_Integer{Integer: 2}},
						{Content: &pb.IDV1_Integer{Integer: 3}},
					}}}}}},
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 8}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Contains}}},
				},
			},
		},
		{
			Desc: "int comparison not in",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Set{datalog.Integer(1), datalog.Integer(2), datalog.Integer(3)}},
				datalog.Value{ID: datalog.Variable(9)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
				datalog.UnaryOp{UnaryOpFunc: datalog.Negate{}},
			},
			Expected: &pb.ExpressionV1{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Set{Set: &pb.IDSet{Set: []*pb.IDV1{
						{Content: &pb.IDV1_Integer{Integer: 1}},
						{Content: &pb.IDV1_Integer{Integer: 2}},
						{Content: &pb.IDV1_Integer{Integer: 3}},
					}}}}}},
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 9}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Contains}}},
					{Content: &pb.Op_Unary{Unary: &pb.OpUnary{Kind: pb.OpUnary_Negate}}},
				},
			},
		},

		{
			Desc: "string comparison equal",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(10)},
				datalog.Value{ID: datalog.String("abcd")},
				datalog.BinaryOp{BinaryOpFunc: datalog.Equal{}},
			},
			Expected: &pb.ExpressionV1{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 10}}}},
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Str{Str: "abcd"}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Equal}}},
				},
			},
		},
		{
			Desc: "string comparison prefix",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(11)},
				datalog.Value{ID: datalog.String("abcd")},
				datalog.BinaryOp{BinaryOpFunc: datalog.Prefix{}},
			},
			Expected: &pb.ExpressionV1{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 11}}}},
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Str{Str: "abcd"}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Prefix}}},
				},
			},
		},
		{
			Desc: "string comparison suffix",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(12)},
				datalog.Value{ID: datalog.String("abcd")},
				datalog.BinaryOp{BinaryOpFunc: datalog.Suffix{}},
			},
			Expected: &pb.ExpressionV1{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 12}}}},
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Str{Str: "abcd"}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Suffix}}},
				},
			},
		},
		{
			Desc: "string comparison in",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Set{datalog.String("a"), datalog.String("b"), datalog.String("c")}},
				datalog.Value{ID: datalog.Variable(13)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
			},
			Expected: &pb.ExpressionV1{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Set{Set: &pb.IDSet{Set: []*pb.IDV1{
						{Content: &pb.IDV1_Str{Str: "a"}},
						{Content: &pb.IDV1_Str{Str: "b"}},
						{Content: &pb.IDV1_Str{Str: "c"}},
					}}}}}},
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 13}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Contains}}},
				},
			},
		},
		{
			Desc: "string comparison not in",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Set{datalog.String("a"), datalog.String("b"), datalog.String("c")}},
				datalog.Value{ID: datalog.Variable(14)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
				datalog.UnaryOp{UnaryOpFunc: datalog.Negate{}},
			},
			Expected: &pb.ExpressionV1{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Set{Set: &pb.IDSet{Set: []*pb.IDV1{
						{Content: &pb.IDV1_Str{Str: "a"}},
						{Content: &pb.IDV1_Str{Str: "b"}},
						{Content: &pb.IDV1_Str{Str: "c"}},
					}}}}}},
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 14}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Contains}}},
					{Content: &pb.Op_Unary{Unary: &pb.OpUnary{Kind: pb.OpUnary_Negate}}},
				},
			},
		},
		{
			Desc: "string regexp",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(15)},
				datalog.Value{ID: datalog.String("abcd")},
				datalog.BinaryOp{BinaryOpFunc: datalog.Regex{}},
			},
			Expected: &pb.ExpressionV1{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 15}}}},
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Str{Str: "abcd"}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Regex}}},
				},
			},
		},
		{
			Desc: "bytes equal",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(16)},
				datalog.Value{ID: datalog.Bytes("abcd")},
				datalog.BinaryOp{BinaryOpFunc: datalog.Equal{}},
			},
			Expected: &pb.ExpressionV1{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 16}}}},
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Bytes{Bytes: []byte("abcd")}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Equal}}},
				},
			},
		},
		{
			Desc: "bytes in",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Set{datalog.Bytes("a"), datalog.Bytes("b"), datalog.Bytes("c")}},
				datalog.Value{ID: datalog.Variable(17)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
			},
			Expected: &pb.ExpressionV1{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Set{Set: &pb.IDSet{Set: []*pb.IDV1{
						{Content: &pb.IDV1_Bytes{Bytes: []byte("a")}},
						{Content: &pb.IDV1_Bytes{Bytes: []byte("b")}},
						{Content: &pb.IDV1_Bytes{Bytes: []byte("c")}},
					}}}}}},
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 17}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Contains}}},
				},
			},
		},
		{
			Desc: "bytes not in",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Set{datalog.Bytes("a"), datalog.Bytes("b"), datalog.Bytes("c")}},
				datalog.Value{ID: datalog.Variable(18)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
				datalog.UnaryOp{UnaryOpFunc: datalog.Negate{}},
			},
			Expected: &pb.ExpressionV1{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Set{Set: &pb.IDSet{Set: []*pb.IDV1{
						{Content: &pb.IDV1_Bytes{Bytes: []byte("a")}},
						{Content: &pb.IDV1_Bytes{Bytes: []byte("b")}},
						{Content: &pb.IDV1_Bytes{Bytes: []byte("c")}},
					}}}}}},
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 18}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Contains}}},
					{Content: &pb.Op_Unary{Unary: &pb.OpUnary{Kind: pb.OpUnary_Negate}}},
				},
			},
		},
		{
			Desc: "symbols in",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Set{datalog.Symbol(1), datalog.Symbol(2), datalog.Symbol(3)}},
				datalog.Value{ID: datalog.Variable(19)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
			},
			Expected: &pb.ExpressionV1{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Set{Set: &pb.IDSet{Set: []*pb.IDV1{
						{Content: &pb.IDV1_Symbol{Symbol: 1}},
						{Content: &pb.IDV1_Symbol{Symbol: 2}},
						{Content: &pb.IDV1_Symbol{Symbol: 3}},
					}}}}}},
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 19}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Contains}}},
				},
			},
		},
		{
			Desc: "symbols not in",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Set{datalog.Symbol(1), datalog.Symbol(2), datalog.Symbol(3)}},
				datalog.Value{ID: datalog.Variable(20)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
				datalog.UnaryOp{UnaryOpFunc: datalog.Negate{}},
			},
			Expected: &pb.ExpressionV1{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Set{Set: &pb.IDSet{Set: []*pb.IDV1{
						{Content: &pb.IDV1_Symbol{Symbol: 1}},
						{Content: &pb.IDV1_Symbol{Symbol: 2}},
						{Content: &pb.IDV1_Symbol{Symbol: 3}},
					}}}}}},
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 20}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Contains}}},
					{Content: &pb.Op_Unary{Unary: &pb.OpUnary{Kind: pb.OpUnary_Negate}}},
				},
			},
		},
		{
			Desc: "add",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(21)},
				datalog.Value{ID: datalog.Integer(42)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Add{}},
			},
			Expected: &pb.ExpressionV1{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 21}}}},
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Integer{Integer: 42}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Add}}},
				},
			},
		},
		{
			Desc: "sub",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(22)},
				datalog.Value{ID: datalog.Integer(42)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Sub{}},
			},
			Expected: &pb.ExpressionV1{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 22}}}},
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Integer{Integer: 42}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Sub}}},
				},
			},
		},
		{
			Desc: "mul",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(23)},
				datalog.Value{ID: datalog.Integer(42)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Mul{}},
			},
			Expected: &pb.ExpressionV1{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 23}}}},
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Integer{Integer: 42}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Mul}}},
				},
			},
		},
		{
			Desc: "div",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(24)},
				datalog.Value{ID: datalog.Integer(42)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Div{}},
			},
			Expected: &pb.ExpressionV1{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 24}}}},
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Integer{Integer: 42}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Div}}},
				},
			},
		},
		{
			Desc: "and",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(25)},
				datalog.Value{ID: datalog.Bool(true)},
				datalog.BinaryOp{BinaryOpFunc: datalog.And{}},
			},
			Expected: &pb.ExpressionV1{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 25}}}},
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Bool{Bool: true}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_And}}},
				},
			},
		},
		{
			Desc: "or",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(26)},
				datalog.Value{ID: datalog.Bool(true)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Or{}},
			},
			Expected: &pb.ExpressionV1{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 26}}}},
					{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Bool{Bool: true}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Or}}},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			out, err := tokenExpressionToProtoExpressionV1(testCase.Input)
			require.NoError(t, err)

			require.Equal(t, testCase.Expected, out)

			dlout, err := protoExpressionToTokenExpressionV1(out)
			require.NoError(t, err)
			require.Equal(t, testCase.Input, dlout)
		})
	}
}

func TestRuleConvertV1(t *testing.T) {
	now := time.Now()

	in := &datalog.Rule{
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

	expectedPbRule := &pb.RuleV1{
		Head: &pb.PredicateV1{Name: 42, Ids: []*pb.IDV1{
			{Content: &pb.IDV1_Integer{Integer: 1}},
			{Content: &pb.IDV1_Str{Str: "id_1"}},
		}},
		Body: []*pb.PredicateV1{
			{
				Name: 43,
				Ids: []*pb.IDV1{
					{Content: &pb.IDV1_Symbol{Symbol: 2}},
					{Content: &pb.IDV1_Date{Date: uint64(now.Unix())}},
				},
			},
			{
				Name: 44,
				Ids: []*pb.IDV1{
					{Content: &pb.IDV1_Bytes{Bytes: []byte("abcd")}},
				},
			},
		},
		Expressions: []*pb.ExpressionV1{
			{Ops: []*pb.Op{
				{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 9}}}},
				{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Integer{Integer: 42}}}},
				{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Equal}}},
			}},
			{Ops: []*pb.Op{
				{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Variable{Variable: 99}}}},
				{Content: &pb.Op_Value{Value: &pb.IDV1{Content: &pb.IDV1_Str{Str: "abcd"}}}},
				{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Prefix}}},
			}},
		},
	}

	pbRule, err := tokenRuleToProtoRuleV1(*in)
	require.NoError(t, err)
	require.Equal(t, expectedPbRule, pbRule)
	out, err := protoRuleToTokenRuleV1(pbRule)
	require.NoError(t, err)
	require.Equal(t, in, out)
}

func TestFactConvertV1(t *testing.T) {
	now := time.Now()
	in := &datalog.Fact{Predicate: datalog.Predicate{
		Name: datalog.Symbol(42),
		IDs: []datalog.ID{
			datalog.Symbol(1),
			datalog.Integer(2),
			datalog.Variable(3),
			datalog.Bytes([]byte("bytes")),
			datalog.String("abcd"),
			datalog.Date(now.Unix()),
			datalog.Bool(true),
			datalog.Set{
				datalog.String("abc"),
				datalog.String("def"),
			},
		},
	}}

	expectedPbFact := &pb.FactV1{Predicate: &pb.PredicateV1{
		Name: 42,
		Ids: []*pb.IDV1{
			{Content: &pb.IDV1_Symbol{Symbol: 1}},
			{Content: &pb.IDV1_Integer{Integer: 2}},
			{Content: &pb.IDV1_Variable{Variable: 3}},
			{Content: &pb.IDV1_Bytes{Bytes: []byte("bytes")}},
			{Content: &pb.IDV1_Str{Str: "abcd"}},
			{Content: &pb.IDV1_Date{Date: uint64(now.Unix())}},
			{Content: &pb.IDV1_Bool{Bool: true}},
			{Content: &pb.IDV1_Set{Set: &pb.IDSet{Set: []*pb.IDV1{
				{Content: &pb.IDV1_Str{Str: "abc"}},
				{Content: &pb.IDV1_Str{Str: "def"}},
			}}}},
		},
	}}

	pbFact, err := tokenFactToProtoFactV1(*in)
	require.NoError(t, err)
	require.Equal(t, expectedPbFact, pbFact)

	out, err := protoFactToTokenFactV1(pbFact)
	require.NoError(t, err)
	require.Equal(t, in, out)
}

func TestConvertInvalidSets(t *testing.T) {
	tokenTestCases := []struct {
		desc string
		in   datalog.Set
	}{
		{
			desc: "empty set",
			in:   datalog.Set{},
		},
		{
			desc: "mixed element types",
			in: datalog.Set{
				datalog.String("abc"),
				datalog.Integer(1),
			},
		},
		{
			desc: "set with variables",
			in: datalog.Set{
				datalog.Variable(0),
				datalog.Variable(1),
			},
		},
		{
			desc: "set with sub sets",
			in: datalog.Set{
				datalog.Set{
					datalog.String("abc"),
					datalog.String("def"),
				},
			},
		},
	}

	protoTestCases := []struct {
		desc string
		in   *pb.IDV1
	}{
		{
			desc: "empty set",
			in: &pb.IDV1{Content: &pb.IDV1_Set{Set: &pb.IDSet{
				Set: []*pb.IDV1{},
			}}},
		},
		{
			desc: "mixed element types",
			in: &pb.IDV1{Content: &pb.IDV1_Set{Set: &pb.IDSet{
				Set: []*pb.IDV1{
					{Content: &pb.IDV1_Str{Str: "abc"}},
					{Content: &pb.IDV1_Integer{Integer: 0}},
				},
			}}},
		},
		{
			desc: "set with variables",
			in: &pb.IDV1{Content: &pb.IDV1_Set{Set: &pb.IDSet{
				Set: []*pb.IDV1{
					{Content: &pb.IDV1_Variable{Variable: 1}},
				},
			}}},
		},
		{
			desc: "set with sub sets",
			in: &pb.IDV1{Content: &pb.IDV1_Set{Set: &pb.IDSet{
				Set: []*pb.IDV1{
					{Content: &pb.IDV1_Set{Set: &pb.IDSet{Set: []*pb.IDV1{
						{Content: &pb.IDV1_Str{Str: "abc"}},
					}}}},
				},
			}}},
		},
	}

	for _, tc := range tokenTestCases {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := tokenIDToProtoIDV1(tc.in)
			require.Error(t, err)
		})
	}

	for _, tc := range protoTestCases {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := protoIDToTokenIDV1(tc.in)
			require.Error(t, err)
		})
	}
}

func TestBlockConvertV1(t *testing.T) {
	predicate := datalog.Predicate{
		Name: datalog.Symbol(12),
		IDs:  []datalog.ID{datalog.String("abcd")},
	}

	pbPredicate := &pb.PredicateV1{
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

	pbRule := &pb.RuleV1{
		Head: pbPredicate,
		Body: []*pb.PredicateV1{pbPredicate},
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
		version: 1,
	}

	expectedPbBlock := &pb.Block{
		Index:   42,
		Symbols: []string{"a", "b", "c", "d"},
		FactsV1: []*pb.FactV1{
			{Predicate: pbPredicate},
		},
		RulesV1:  []*pb.RuleV1{pbRule},
		ChecksV1: []*pb.CheckV1{{Queries: []*pb.RuleV1{pbRule}}},
		Context:  "context",
		Version:  1,
	}

	pbBlock, err := tokenBlockToProtoBlock(in)
	require.NoError(t, err)
	require.Equal(t, expectedPbBlock, pbBlock)

	out, err := protoBlockToTokenBlock(pbBlock)
	require.NoError(t, err)
	require.Equal(t, in, out)

	pbBlock.Version = MaxSchemaVersion + 1
	_, err = protoBlockToTokenBlock(pbBlock)
	require.Error(t, err)
}
