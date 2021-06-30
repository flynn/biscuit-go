package parser

import (
	"testing"

	"github.com/alecthomas/participle/v2"
	"github.com/stretchr/testify/require"
)

func TestGrammarPredicate(t *testing.T) {
	parser, err := participle.Build(&Predicate{}, DefaultParserOptions...)
	require.NoError(t, err)

	testCases := []struct {
		Input    string
		Expected *Predicate
	}{
		{
			Input: `resource(#ambient, $var1)`,
			Expected: &Predicate{
				Name: sptr("resource"),
				IDs: []*Term{
					{Symbol: symptr("ambient")},
					{Variable: varptr("var1")},
				},
			},
		},
		{
			Input: `resource(#ambient, $0, #read)`,
			Expected: &Predicate{
				Name: sptr("resource"),
				IDs: []*Term{
					{Symbol: symptr("ambient")},
					{Variable: varptr("0")},
					{Symbol: symptr("read")},
				},
			},
		},
		{
			Input: `right(#authority, "/a/file1.txt", #read)`,
			Expected: &Predicate{
				Name: sptr("right"),
				IDs: []*Term{
					{Symbol: symptr("authority")},
					{String: sptr("/a/file1.txt")},
					{Symbol: symptr("read")},
				},
			},
		},
		{
			Input: `right("/a/file1.txt", #read)`,
			Expected: &Predicate{
				Name: sptr("right"),
				IDs: []*Term{
					{String: sptr("/a/file1.txt")},
					{Symbol: symptr("read")},
				},
			},
		},
		{
			Input: `right("/a/file1.txt", $1)`,
			Expected: &Predicate{
				Name: sptr("right"),
				IDs: []*Term{
					{String: sptr("/a/file1.txt")},
					{Variable: varptr("1")},
				},
			},
		},
		{
			Input: `right($1, "hex:41414141")`,
			Expected: &Predicate{
				Name: sptr("right"),
				IDs: []*Term{
					{Variable: varptr("1")},
					{Bytes: hexsptr("41414141")},
				},
			},
		},
		{
			Input: `right($1, ["hex:41414141", #sym])`,
			Expected: &Predicate{
				Name: sptr("right"),
				IDs: []*Term{
					{Variable: varptr("1")},
					{Set: []*Term{{Bytes: hexsptr("41414141")}, {Symbol: symptr("sym")}}},
				},
			},
		},
		{
			Input: `right($1, true, false)`,
			Expected: &Predicate{
				Name: sptr("right"),
				IDs: []*Term{
					{Variable: varptr("1")},
					{Bool: boolptr(true)},
					{Bool: boolptr(false)},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Input, func(t *testing.T) {
			parsed := &Predicate{}
			err := parser.ParseString("test", testCase.Input, parsed)
			require.NoError(t, err)
			require.Equal(t, testCase.Expected, parsed)
		})
	}
}

func TestGrammarConstraint(t *testing.T) {
	parser, err := participle.Build(&Constraint{}, DefaultParserOptions...)
	require.NoError(t, err)

	testCases := []struct {
		Input    string
		Expected *Constraint
	}{
		{
			Input: `$0 == 1`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: varptr("0"),
					Int: &IntComparison{
						Operation: sptr("=="),
						Target:    i64ptr(1),
					},
				},
			},
		},
		{
			Input: `$1 > 2`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: varptr("1"),
					Int: &IntComparison{
						Operation: sptr(">"),
						Target:    i64ptr(2),
					},
				},
			},
		},
		{
			Input: `$0 >= 1`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: varptr("0"),
					Int: &IntComparison{
						Operation: sptr(">="),
						Target:    i64ptr(1),
					},
				},
			},
		},
		{
			Input: `$0 < 1`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: varptr("0"),
					Int: &IntComparison{
						Operation: sptr("<"),
						Target:    i64ptr(1),
					},
				},
			},
		},
		{
			Input: `$0 <= 1`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: varptr("0"),
					Int: &IntComparison{
						Operation: sptr("<="),
						Target:    i64ptr(1),
					},
				},
			},
		},
		{
			Input: `$0 in [1, 2, 3]`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: varptr("0"),
					Set: &Set{
						Int: []int64{1, 2, 3},
						Not: false,
					},
				},
			},
		},
		{
			Input: `$0 not in [4,5,6]`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: varptr("0"),
					Set: &Set{
						Int: []int64{4, 5, 6},
						Not: true,
					},
				},
			},
		},
		{
			Input: `$0 == "abc"`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: varptr("0"),
					String: &StringComparison{
						Operation: sptr("=="),
						Target:    sptr("abc"),
					},
				},
			},
		},
		{
			Input: `prefix($0, "abc")`,
			Expected: &Constraint{
				FunctionConstraint: &FunctionConstraint{
					Function: sptr("prefix"),
					Variable: varptr("0"),
					Argument: sptr("abc"),
				},
			},
		},
		{
			Input: `suffix($0, "abc")`,
			Expected: &Constraint{
				FunctionConstraint: &FunctionConstraint{
					Function: sptr("suffix"),
					Variable: varptr("0"),
					Argument: sptr("abc"),
				},
			},
		},
		{
			Input: `match($0, "^abc[a-z]+$") `,
			Expected: &Constraint{
				FunctionConstraint: &FunctionConstraint{
					Function: sptr("match"),
					Variable: varptr("0"),
					Argument: sptr("^abc[a-z]+$"),
				},
			},
		},
		{
			Input: `$0 in ["abc", "def"]`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: varptr("0"),
					Set: &Set{
						String: []string{"abc", "def"},
						Not:    false,
					},
				},
			},
		},
		{
			Input: `$0 not in ["abc", "def"]`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: varptr("0"),
					Set: &Set{
						String: []string{"abc", "def"},
						Not:    true,
					},
				},
			},
		},
		{
			Input: `$0 <= "2006-01-02T15:04:05Z07:00"`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: varptr("0"),
					Date: &DateComparison{
						Operation: sptr("<="),
						Target:    sptr("2006-01-02T15:04:05Z07:00"),
					},
				},
			},
		},
		{
			Input: `$0 >= "2006-01-02T15:04:05Z07:00"`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: varptr("0"),
					Date: &DateComparison{
						Operation: sptr(">="),
						Target:    sptr("2006-01-02T15:04:05Z07:00"),
					},
				},
			},
		},
		{
			Input: `$0 in [#a, #b, #c]`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: varptr("0"),
					Set: &Set{
						Symbols: []Symbol{"a", "b", "c"},
						Not:     false,
					},
				},
			},
		},
		{
			Input: `$0 not in [#a, #b, #c]`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: varptr("0"),
					Set: &Set{
						Symbols: []Symbol{"a", "b", "c"},
						Not:     true,
					},
				},
			},
		},
		{
			Input: `$0 in ["hex:41", "hex:42", "hex:43"]`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: varptr("0"),
					Set: &Set{
						Bytes: []HexString{"41", "42", "43"},
						Not:   false,
					},
				},
			},
		},
		{
			Input: `$0 not in ["hex:abcdef", "hex:01234", "hex:56789"]`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: varptr("0"),
					Set: &Set{
						Bytes: []HexString{"abcdef", "01234", "56789"},
						Not:   true,
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Input, func(t *testing.T) {
			parsed := &Constraint{}
			err := parser.ParseString("test", testCase.Input, parsed)
			require.NoError(t, err)
			require.Equal(t, testCase.Expected, parsed)
		})
	}

}

func TestGrammarCheck(t *testing.T) {
	parser, err := participle.Build(&Check{}, DefaultParserOptions...)
	require.NoError(t, err)

	testCases := []struct {
		Input    string
		Expected *Check
	}{
		{
			Input: `[grandparent(#a, #c) <- parent(#a, #b), parent(#b, #c)]`,
			Expected: &Check{[]*Rule{
				{
					Head: &Predicate{
						Name: sptr("grandparent"),
						IDs: []*Term{
							{Symbol: symptr("a")},
							{Symbol: symptr("c")},
						},
					},
					Body: []*Predicate{
						{
							Name: sptr("parent"),
							IDs: []*Term{
								{Symbol: symptr("a")},
								{Symbol: symptr("b")},
							},
						},
						{
							Name: sptr("parent"),
							IDs: []*Term{
								{Symbol: symptr("b")},
								{Symbol: symptr("c")},
							},
						},
					},
				},
			}},
		},
		{
			Input: `[empty() <- parent(#a, #b), parent(#b, #c)]`,
			Expected: &Check{[]*Rule{
				{
					Head: &Predicate{
						Name: sptr("empty"),
						IDs:  nil,
					},
					Body: []*Predicate{
						{
							Name: sptr("parent"),
							IDs: []*Term{
								{Symbol: symptr("a")},
								{Symbol: symptr("b")},
							},
						},
						{
							Name: sptr("parent"),
							IDs: []*Term{
								{Symbol: symptr("b")},
								{Symbol: symptr("c")},
							},
						},
					},
				},
			}},
		},
		{
			Input: `[grandparent(#a, #c) <- parent(#a, #b), parent(#b, #c) || grandparent(#a, #c) <- parent(#a, #b), parent(#b, #c) @ $0 > 42, prefix($1, "test")]`,
			Expected: &Check{[]*Rule{
				{
					Head: &Predicate{
						Name: sptr("grandparent"),
						IDs: []*Term{
							{Symbol: symptr("a")},
							{Symbol: symptr("c")},
						},
					},
					Body: []*Predicate{
						{
							Name: sptr("parent"),
							IDs: []*Term{
								{Symbol: symptr("a")},
								{Symbol: symptr("b")},
							},
						},
						{
							Name: sptr("parent"),
							IDs: []*Term{
								{Symbol: symptr("b")},
								{Symbol: symptr("c")},
							},
						},
					},
				},
				{
					Head: &Predicate{
						Name: sptr("grandparent"),
						IDs: []*Term{
							{Symbol: symptr("a")},
							{Symbol: symptr("c")},
						},
					},
					Body: []*Predicate{
						{
							Name: sptr("parent"),
							IDs: []*Term{
								{Symbol: symptr("a")},
								{Symbol: symptr("b")},
							},
						},
						{
							Name: sptr("parent"),
							IDs: []*Term{
								{Symbol: symptr("b")},
								{Symbol: symptr("c")},
							},
						},
					},
					Constraints: []*Constraint{
						{
							VariableConstraint: &VariableConstraint{
								Variable: varptr("0"),
								Int: &IntComparison{
									Operation: sptr(">"),
									Target:    i64ptr(42),
								},
							},
						},
						{
							FunctionConstraint: &FunctionConstraint{
								Function: sptr("prefix"),
								Variable: varptr("1"),
								Argument: sptr("test"),
							},
						},
					},
				},
			}},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Input, func(t *testing.T) {
			parsed := &Check{}
			err := parser.ParseString("test", testCase.Input, parsed)
			require.NoError(t, err)
			require.Equal(t, testCase.Expected, parsed)
		})
	}
}

func TestGrammarRule(t *testing.T) {
	parser, err := participle.Build(&Rule{}, DefaultParserOptions...)
	require.NoError(t, err)

	testCases := []struct {
		Input    string
		Expected *Rule
	}{
		{
			Input: `// some comment
	grandparent(#a, #c) <- parent(#a, #b), parent(#b, #c)`,
			Expected: &Rule{
				Comments: []*Comment{commentptr("some comment")},
				Head: &Predicate{
					Name: sptr("grandparent"),
					IDs: []*Term{
						{Symbol: symptr("a")},
						{Symbol: symptr("c")},
					},
				},
				Body: []*Predicate{
					{
						Name: sptr("parent"),
						IDs: []*Term{
							{Symbol: symptr("a")},
							{Symbol: symptr("b")},
						},
					},
					{
						Name: sptr("parent"),
						IDs: []*Term{
							{Symbol: symptr("b")},
							{Symbol: symptr("c")},
						},
					},
				},
			},
		},
		{
			Input: `empty() <- parent(#a, #b), parent(#b, #c)`,
			Expected: &Rule{
				Head: &Predicate{
					Name: sptr("empty"),
				},
				Body: []*Predicate{
					{
						Name: sptr("parent"),
						IDs: []*Term{
							{Symbol: symptr("a")},
							{Symbol: symptr("b")},
						},
					},
					{
						Name: sptr("parent"),
						IDs: []*Term{
							{Symbol: symptr("b")},
							{Symbol: symptr("c")},
						},
					},
				},
			},
		},
		{
			Input: `grandparent(#a, #c) <- parent(#a, #b), parent(#b, #c) @ $0 > 42, prefix($1, "test")`,
			Expected: &Rule{
				Head: &Predicate{
					Name: sptr("grandparent"),
					IDs: []*Term{
						{Symbol: symptr("a")},
						{Symbol: symptr("c")},
					},
				},
				Body: []*Predicate{
					{
						Name: sptr("parent"),
						IDs: []*Term{
							{Symbol: symptr("a")},
							{Symbol: symptr("b")},
						},
					},
					{
						Name: sptr("parent"),
						IDs: []*Term{
							{Symbol: symptr("b")},
							{Symbol: symptr("c")},
						},
					},
				},
				Constraints: []*Constraint{
					{
						VariableConstraint: &VariableConstraint{
							Variable: varptr("0"),
							Int: &IntComparison{
								Operation: sptr(">"),
								Target:    i64ptr(42),
							},
						},
					},
					{
						FunctionConstraint: &FunctionConstraint{
							Function: sptr("prefix"),
							Variable: varptr("1"),
							Argument: sptr("test"),
						},
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Input, func(t *testing.T) {
			parsed := &Rule{}
			err := parser.ParseString("test", testCase.Input, parsed)
			require.NoError(t, err)
			require.Equal(t, testCase.Expected, parsed)
		})
	}
}

func symptr(s string) *Symbol {
	sym := Symbol(s)
	return &sym
}

func varptr(s string) *Variable {
	v := Variable(s)
	return &v
}

func sptr(s string) *string {
	return &s
}

func i64ptr(i int64) *int64 {
	return &i
}

func hexsptr(s string) *HexString {
	h := HexString(s)
	return &h
}

func commentptr(s string) *Comment {
	c := Comment(s)
	return &c
}

func boolptr(b bool) *Bool {
	v := Bool(b)
	return &v
}
