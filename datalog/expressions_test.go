package datalog

import (
	"errors"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func idptr(v ID) *ID {
	return &v
}

func TestUnaryNegate(t *testing.T) {
	ops := Expression{
		Value{Bool(true)},
		UnaryOp{Negate{}},
		UnaryOp{Negate{}},
	}

	res, err := ops.Evaluate(nil)
	require.NoError(t, err)
	require.Equal(t, Bool(true), res)
}

func TestUnaryParens(t *testing.T) {
	ops := Expression{
		Value{Integer(1)},
		Value{Variable(2)},
		Value{Integer(3)},
		BinaryOp{Mul{}},
		BinaryOp{Add{}},
	}

	values := map[Variable]*ID{
		2: idptr(Integer(2)),
	}

	res, err := ops.Evaluate(values)
	require.NoError(t, err)
	require.Equal(t, Integer(7), res)

	ops = Expression{
		Value{Integer(1)},
		Value{Variable(2)},
		BinaryOp{Add{}},
		UnaryOp{Parens{}},
		Value{Integer(3)},
		BinaryOp{Mul{}},
	}

	res, err = ops.Evaluate(values)
	require.NoError(t, err)
	require.Equal(t, Integer(9), res)
}

func TestBinaryLessThan(t *testing.T) {
	require.Equal(t, BinaryLessThan, LessThan{}.Type())

	testCases := []struct {
		desc        string
		left        ID
		right       ID
		res         Bool
		expectedErr bool
	}{
		{
			desc:  "not less than",
			left:  Integer(5),
			right: Integer(3),
			res:   false,
		},
		{
			desc:  "not less than negative",
			left:  Integer(0),
			right: Integer(-7),
			res:   false,
		},
		{
			desc:  "less than",
			left:  Integer(3),
			right: Integer(7),
			res:   true,
		},
		{
			desc:  "less than negative",
			left:  Integer(-10),
			right: Integer(-3),
			res:   true,
		},
		{
			desc:  "equal check",
			left:  Integer(42),
			right: Integer(42),
			res:   false,
		},
		{
			desc:        "invalid left type errors",
			left:        Symbol(42),
			right:       Integer(42),
			expectedErr: true,
		},
		{
			desc:        "invalid right type errors",
			left:        Integer(42),
			right:       String("abc"),
			expectedErr: true,
		},
		{
			desc:        "invalid both type errors",
			left:        String("def"),
			right:       String("abc"),
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{LessThan{}},
			}

			res, err := ops.Evaluate(nil)
			if tc.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestBinaryLessOrEqual(t *testing.T) {
	require.Equal(t, BinaryLessOrEqual, LessOrEqual{}.Type())

	testCases := []struct {
		desc        string
		left        ID
		right       ID
		res         Bool
		expectedErr bool
	}{
		{
			desc:  "not less or equal integers",
			left:  Integer(5),
			right: Integer(3),
			res:   false,
		},
		{
			desc:  "not less or equal dates",
			left:  Date(5),
			right: Date(3),
			res:   false,
		},
		{
			desc:  "not less or equal negative integers",
			left:  Integer(0),
			right: Integer(-7),
			res:   false,
		},
		{
			desc:  "less integers",
			left:  Integer(3),
			right: Integer(7),
			res:   true,
		},
		{
			desc:  "less dates",
			left:  Date(0),
			right: Date(3),
			res:   true,
		},
		{
			desc:  "less negative integers",
			left:  Integer(-10),
			right: Integer(-3),
			res:   true,
		},
		{
			desc:  "equal checks integers",
			left:  Integer(42),
			right: Integer(42),
			res:   true,
		},
		{
			desc:  "equal checks dates",
			left:  Date(3),
			right: Date(3),
			res:   true,
		},
		{
			desc:  "equal checks negative integers",
			left:  Integer(-1),
			right: Integer(-1),
			res:   true,
		},
		{
			desc:        "invalid left type errors",
			left:        Symbol(42),
			right:       Integer(42),
			expectedErr: true,
		},
		{
			desc:        "invalid right type errors",
			left:        Integer(42),
			right:       String("abc"),
			expectedErr: true,
		},
		{
			desc:        "invalid both type errors",
			left:        String("def"),
			right:       String("abc"),
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{LessOrEqual{}},
			}

			res, err := ops.Evaluate(nil)
			if tc.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestBinaryGreaterThan(t *testing.T) {
	require.Equal(t, BinaryGreaterThan, GreaterThan{}.Type())

	testCases := []struct {
		desc        string
		left        ID
		right       ID
		res         Bool
		expectedErr bool
	}{
		{
			desc:  "not greater than",
			left:  Integer(3),
			right: Integer(5),
			res:   false,
		},
		{
			desc:  "not greater than negative",
			left:  Integer(-7),
			right: Integer(0),
			res:   false,
		},
		{
			desc:  "greater than",
			left:  Integer(7),
			right: Integer(3),
			res:   true,
		},
		{
			desc:  "greater than negative",
			left:  Integer(-3),
			right: Integer(-10),
			res:   true,
		},
		{
			desc:  "equal check",
			left:  Integer(42),
			right: Integer(42),
			res:   false,
		},
		{
			desc:        "invalid left type errors",
			left:        Symbol(42),
			right:       Integer(42),
			expectedErr: true,
		},
		{
			desc:        "invalid right type errors",
			left:        Integer(42),
			right:       String("abc"),
			expectedErr: true,
		},
		{
			desc:        "invalid both type errors",
			left:        String("def"),
			right:       String("abc"),
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{GreaterThan{}},
			}

			res, err := ops.Evaluate(nil)
			if tc.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestBinaryGreaterOrEqual(t *testing.T) {
	require.Equal(t, BinaryGreaterOrEqual, GreaterOrEqual{}.Type())

	testCases := []struct {
		desc        string
		left        ID
		right       ID
		res         Bool
		expectedErr bool
	}{
		{
			desc:  "not greater or equal integers",
			left:  Integer(3),
			right: Integer(5),
			res:   false,
		},
		{
			desc:  "not greater or equal dates",
			left:  Date(3),
			right: Date(5),
			res:   false,
		},
		{
			desc:  "not greater or equal negative integers",
			left:  Integer(-7),
			right: Integer(0),
			res:   false,
		},
		{
			desc:  "greater integers",
			left:  Integer(7),
			right: Integer(3),
			res:   true,
		},
		{
			desc:  "greater dates",
			left:  Date(3),
			right: Date(0),
			res:   true,
		},
		{
			desc:  "greater negative integers",
			left:  Integer(-3),
			right: Integer(-10),
			res:   true,
		},
		{
			desc:  "equal checks integers",
			left:  Integer(42),
			right: Integer(42),
			res:   true,
		},
		{
			desc:  "equal checks dates",
			left:  Date(3),
			right: Date(3),
			res:   true,
		},
		{
			desc:  "equal checks negative integers",
			left:  Integer(-1),
			right: Integer(-1),
			res:   true,
		},
		{
			desc:        "invalid left type errors",
			left:        Symbol(42),
			right:       Integer(42),
			expectedErr: true,
		},
		{
			desc:        "invalid right type errors",
			left:        Integer(42),
			right:       String("abc"),
			expectedErr: true,
		},
		{
			desc:        "invalid both type errors",
			left:        String("def"),
			right:       String("abc"),
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{GreaterOrEqual{}},
			}

			res, err := ops.Evaluate(nil)
			if tc.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestBinaryEqual(t *testing.T) {
	require.Equal(t, BinaryEqual, Equal{}.Type())

	testCases := []struct {
		desc        string
		left        ID
		right       ID
		res         Bool
		expectedErr bool
	}{
		{
			desc:  "not equal integers",
			left:  Integer(3),
			right: Integer(5),
			res:   false,
		},
		{
			desc:  "not equal bytes",
			left:  Bytes{0},
			right: Bytes{1},
			res:   false,
		},
		{
			desc:  "not equal string",
			left:  String("abc"),
			right: String("def"),
			res:   false,
		},
		{
			desc:  "equal integers",
			left:  Integer(3),
			right: Integer(3),
			res:   true,
		},
		{
			desc:  "equal bytes",
			left:  Bytes{0, 1, 2},
			right: Bytes{0, 1, 2},
			res:   true,
		},
		{
			desc:  "equal strings",
			left:  String("abc"),
			right: String("abc"),
			res:   true,
		},
		{
			desc:        "invalid left type errors",
			left:        Symbol(42),
			right:       Integer(42),
			expectedErr: true,
		},
		{
			desc:        "invalid right type errors",
			left:        Integer(42),
			right:       String("abc"),
			expectedErr: true,
		},
		{
			desc:        "invalid both type errors",
			left:        Symbol(0),
			right:       Symbol(0),
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{Equal{}},
			}

			res, err := ops.Evaluate(nil)
			if tc.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestBinaryContains(t *testing.T) {
	require.Equal(t, BinaryContains, Contains{}.Type())

	tests := []struct {
		name    string
		left    ID
		right   ID
		want    ID
		wantErr bool
	}{
		{
			name:  "integer in set",
			left:  Set{Integer(1), Integer(2), Integer(3)},
			right: Integer(1),
			want:  Bool(true),
		},
		{
			name:  "string not in set",
			left:  Set{String("def"), String("ijk")},
			right: String("abc"),
			want:  Bool(false),
		},
		{
			name:  "bytes in set",
			left:  Set{Bytes("abc"), Bytes("def")},
			right: Bytes("abc"),
			want:  Bool(true),
		},
		{
			name:  "symbol not in set",
			left:  Set{Symbol(1), Symbol(2)},
			right: Symbol(0),
			want:  Bool(false),
		},
		{
			name:    "set element type mismatch",
			left:    Set{Integer(1), Integer(2)},
			right:   Symbol(0),
			wantErr: true,
		},
		{
			name:    "unsupported type Bool",
			left:    Set{Bool(true), Bool(false)},
			right:   Bool(true),
			wantErr: true,
		},
		{
			name:    "unsupported type Date",
			left:    Set{Date(1), Date(2)},
			right:   Date(0),
			wantErr: true,
		},
		{
			name:    "unsupported type Set",
			left:    Set{Integer(1), Integer(2)},
			right:   Set{Integer(0)},
			wantErr: true,
		},
		{
			name:    "unsupported type Set",
			left:    Set{Variable(1), Variable(2)},
			right:   Integer(0),
			wantErr: true,
		},
		{
			name:    "invalid left type",
			left:    Set{Integer(1), Integer(2)},
			right:   Variable(0),
			wantErr: true,
		},
		{
			name:    "invalid right type not a set",
			left:    Integer(0),
			right:   Integer(0),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Contains{}.Eval(tt.left, tt.right)
			require.Equal(t, tt.wantErr, (err != nil))
			require.Equal(t, tt.want, got)
		})
	}
}

func TestBinaryPrefix(t *testing.T) {
	require.Equal(t, BinaryPrefix, Prefix{}.Type())

	testCases := []struct {
		desc        string
		left        ID
		right       ID
		res         Bool
		expectedErr bool
	}{
		{
			desc:  "prefix",
			left:  String("abcdef"),
			right: String("abc"),
			res:   true,
		},
		{
			desc:  "not prefix",
			left:  String("abcdef"),
			right: String("def"),
			res:   false,
		},
		{
			desc:  "not prefix 2",
			left:  String("abc"),
			right: String("abcdef"),
			res:   false,
		},
		{
			desc:        "invalid left type errors",
			left:        Symbol(42),
			right:       String("abc"),
			expectedErr: true,
		},
		{
			desc:        "invalid right type errors",
			left:        String("abc"),
			right:       Integer(42),
			expectedErr: true,
		},
		{
			desc:        "invalid both type errors",
			left:        Symbol(0),
			right:       Symbol(0),
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{Prefix{}},
			}

			res, err := ops.Evaluate(nil)
			if tc.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestBinarySuffix(t *testing.T) {
	require.Equal(t, BinarySuffix, Suffix{}.Type())

	testCases := []struct {
		desc        string
		left        ID
		right       ID
		res         Bool
		expectedErr bool
	}{
		{
			desc:  "suffix",
			left:  String("abcdef"),
			right: String("def"),
			res:   true,
		},
		{
			desc:  "not suffix",
			left:  String("abcdef"),
			right: String("abc"),
			res:   false,
		},
		{
			desc:  "not suffix 2",
			left:  String("def"),
			right: String("abcdef"),
			res:   false,
		},
		{
			desc:        "invalid left type errors",
			left:        Symbol(42),
			right:       String("abc"),
			expectedErr: true,
		},
		{
			desc:        "invalid right type errors",
			left:        String("abc"),
			right:       Integer(42),
			expectedErr: true,
		},
		{
			desc:        "invalid both type errors",
			left:        Symbol(0),
			right:       Symbol(0),
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{Suffix{}},
			}

			res, err := ops.Evaluate(nil)
			if tc.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestBinaryRegex(t *testing.T) {
	require.Equal(t, BinaryRegex, Regex{}.Type())
	testCases := []struct {
		desc        string
		left        ID
		right       ID
		res         Bool
		expectedErr bool
	}{
		{
			desc:  "regex match",
			left:  String("abcdef"),
			right: String("def$"),
			res:   true,
		},
		{
			desc:  "regex match 2",
			left:  String("abcdef"),
			right: String("[a-f]{6}"),
			res:   true,
		},
		{
			desc:  "regex no match",
			left:  String("abc"),
			right: String("ABC"),
			res:   false,
		},
		{
			desc:        "invalid left type errors",
			left:        Symbol(42),
			right:       String("abc"),
			expectedErr: true,
		},
		{
			desc:        "invalid right type errors",
			left:        String("abc"),
			right:       Integer(42),
			expectedErr: true,
		},
		{
			desc:        "invalid both type errors",
			left:        Symbol(0),
			right:       Symbol(0),
			expectedErr: true,
		},
		{
			desc:        "invalid regexp",
			left:        String("abc"),
			right:       String("[abc"),
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{Regex{}},
			}

			res, err := ops.Evaluate(nil)
			if tc.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestBinaryAdd(t *testing.T) {
	require.Equal(t, BinaryAdd, Add{}.Type())
	testCases := []struct {
		desc            string
		left            ID
		right           ID
		res             ID
		expectedErr     bool
		expectedErrType error
	}{
		{
			desc:  "normal addition",
			left:  Integer(5),
			right: Integer(3),
			res:   Integer(8),
		},
		{
			desc:  "addition with negative numbers",
			left:  Integer(10),
			right: Integer(-7),
			res:   Integer(3),
		},
		{
			desc:  "addition with negative numbers 2",
			left:  Integer(-7),
			right: Integer(-3),
			res:   Integer(-10),
		},
		{
			desc:        "invalid left type",
			left:        String("abc"),
			right:       Integer(-3),
			expectedErr: true,
		},
		{
			desc:        "invalid right type",
			left:        Integer(-3),
			right:       String("abc"),
			expectedErr: true,
		},
		{
			desc:            "handle overflow errors",
			left:            Integer(math.MaxInt64),
			right:           Integer(1),
			expectedErr:     true,
			expectedErrType: ErrInt64Overflow,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{Add{}},
			}

			res, err := ops.Evaluate(nil)
			if tc.expectedErr {
				if tc.expectedErrType != nil {
					require.Equal(t, tc.expectedErrType, errors.Unwrap(err))
				} else {
					require.Error(t, err)
				}
			} else {
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestBinarySub(t *testing.T) {
	require.Equal(t, BinarySub, Sub{}.Type())
	testCases := []struct {
		desc            string
		left            ID
		right           ID
		res             ID
		expectedErr     bool
		expectedErrType error
	}{
		{
			desc:  "normal substraction",
			left:  Integer(5),
			right: Integer(3),
			res:   Integer(2),
		},
		{
			desc:  "substraction with negative numbers",
			left:  Integer(10),
			right: Integer(-7),
			res:   Integer(17),
		},
		{
			desc:  "substraction with negative numbers 2",
			left:  Integer(-7),
			right: Integer(-3),
			res:   Integer(-4),
		},
		{
			desc:        "invalid left type",
			left:        String("abc"),
			right:       Integer(-3),
			expectedErr: true,
		},
		{
			desc:        "invalid right type",
			left:        Integer(-3),
			right:       String("abc"),
			expectedErr: true,
		},
		{
			desc:            "handle overflow errors",
			left:            Integer(math.MinInt64),
			right:           Integer(1),
			expectedErr:     true,
			expectedErrType: ErrInt64Overflow,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{Sub{}},
			}

			res, err := ops.Evaluate(nil)
			if tc.expectedErr {
				if tc.expectedErrType != nil {
					require.Equal(t, tc.expectedErrType, errors.Unwrap(err))
				} else {
					require.Error(t, err)
				}
			} else {
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestBinaryMul(t *testing.T) {
	require.Equal(t, BinaryMul, Mul{}.Type())
	testCases := []struct {
		desc            string
		left            ID
		right           ID
		res             ID
		expectedErr     bool
		expectedErrType error
	}{
		{
			desc:  "normal multiplication",
			left:  Integer(5),
			right: Integer(3),
			res:   Integer(15),
		},
		{
			desc:  "multiplication with negative numbers",
			left:  Integer(10),
			right: Integer(-7),
			res:   Integer(-70),
		},
		{
			desc:  "multiplication with negative numbers 2",
			left:  Integer(-7),
			right: Integer(-3),
			res:   Integer(21),
		},
		{
			desc:        "invalid left type",
			left:        String("abc"),
			right:       Integer(-3),
			expectedErr: true,
		},
		{
			desc:        "invalid right type",
			left:        Integer(-3),
			right:       String("abc"),
			expectedErr: true,
		},
		{
			desc:            "handle overflow errors",
			left:            Integer(math.MaxInt64),
			right:           Integer(math.MaxInt64),
			expectedErr:     true,
			expectedErrType: ErrInt64Overflow,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{Mul{}},
			}

			res, err := ops.Evaluate(nil)
			if tc.expectedErr {
				if tc.expectedErrType != nil {
					require.Equal(t, tc.expectedErrType, errors.Unwrap(err))
				} else {
					require.Error(t, err)
				}
			} else {
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestBinaryDiv(t *testing.T) {
	require.Equal(t, BinaryDiv, Div{}.Type())
	testCases := []struct {
		desc            string
		left            ID
		right           ID
		res             ID
		expectedErr     bool
		expectedErrType error
	}{
		{
			desc:  "euclidian division",
			left:  Integer(32),
			right: Integer(4),
			res:   Integer(8),
		},
		{
			desc:  "euclidian division with reminder",
			left:  Integer(33),
			right: Integer(4),
			res:   Integer(8),
		},
		{
			desc:        "invalid left type",
			left:        String("abc"),
			right:       Integer(-3),
			expectedErr: true,
		},
		{
			desc:        "invalid right type",
			left:        Integer(-3),
			right:       String("abc"),
			expectedErr: true,
		},
		{
			desc:            "division by zero",
			left:            Integer(32),
			right:           Integer(0),
			expectedErr:     true,
			expectedErrType: ErrExprDivByZero,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{Div{}},
			}

			res, err := ops.Evaluate(nil)
			if tc.expectedErr {
				if tc.expectedErrType != nil {
					require.Equal(t, tc.expectedErrType, errors.Unwrap(err))
				} else {
					require.Error(t, err)
				}
			} else {
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestBinaryAnd(t *testing.T) {
	require.Equal(t, BinaryAnd, And{}.Type())

	testCases := []struct {
		desc        string
		left        ID
		right       ID
		res         Bool
		expectedErr bool
	}{
		{
			desc:  "and 1",
			left:  Bool(true),
			right: Bool(true),
			res:   true,
		},
		{
			desc:  "and 2",
			left:  Bool(true),
			right: Bool(false),
			res:   false,
		},
		{
			desc:  "and 3",
			left:  Bool(false),
			right: Bool(true),
			res:   false,
		},
		{
			desc:  "and 4",
			left:  Bool(false),
			right: Bool(false),
			res:   false,
		},
		{
			desc:        "invalid left type",
			left:        Integer(0),
			right:       Bool(true),
			expectedErr: true,
		},
		{
			desc:        "invalid right type",
			left:        Bool(true),
			right:       String("abc"),
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{And{}},
			}

			res, err := ops.Evaluate(nil)
			if tc.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestBinaryOr(t *testing.T) {
	require.Equal(t, BinaryOr, Or{}.Type())

	testCases := []struct {
		desc        string
		left        ID
		right       ID
		res         Bool
		expectedErr bool
	}{
		{
			desc:  "or 1",
			left:  Bool(true),
			right: Bool(true),
			res:   true,
		},
		{
			desc:  "or 2",
			left:  Bool(true),
			right: Bool(false),
			res:   true,
		},
		{
			desc:  "or 3",
			left:  Bool(false),
			right: Bool(true),
			res:   true,
		},
		{
			desc:  "or 4",
			left:  Bool(false),
			right: Bool(false),
			res:   false,
		},
		{
			desc:        "invalid left type",
			left:        Integer(0),
			right:       Bool(true),
			expectedErr: true,
		},
		{
			desc:        "invalid right type",
			left:        Bool(true),
			right:       String("abc"),
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{Or{}},
			}

			res, err := ops.Evaluate(nil)
			if tc.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.res, res)
			}
		})
	}
}
