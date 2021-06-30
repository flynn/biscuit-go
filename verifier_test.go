package biscuit

import (
	"crypto/rand"
	"testing"

	"github.com/biscuit-auth/biscuit-go/sig"
	"github.com/stretchr/testify/require"
)

func TestVerifierDefaultPolicy(t *testing.T) {
	rng := rand.Reader
	root := sig.GenerateKeypair(rng)

	builder := NewBuilder(root)
	err := builder.AddAuthorityFact(Fact{Predicate{
		Name: "right",
		IDs: []Term{
			Symbol("authority"),
			String("/a/file1.txt"),
			Symbol("read"),
		},
	}})
	require.NoError(t, err)

	b, err := builder.Build()
	require.NoError(t, err)

	v, err := b.Verify(root.Public())
	require.NoError(t, err)

	v.AddPolicy(DefaultDenyPolicy)
	err = v.Verify()
	require.Equal(t, err, ErrPolicyDenied)

	v.Reset()
	v.AddPolicy(DefaultAllowPolicy)
	require.NoError(t, v.Verify())
}

func TestVerifierPolicies(t *testing.T) {
	rng := rand.Reader
	root := sig.GenerateKeypair(rng)

	builder := NewBuilder(root)
	err := builder.AddAuthorityRule(Rule{
		Head: Predicate{Name: "right", IDs: []Term{SymbolAuthority, Variable("file"), Variable("operation")}},
		Body: []Predicate{
			{Name: "resource", IDs: []Term{Symbol("ambient"), Variable("file")}},
			{Name: "operation", IDs: []Term{Symbol("ambient"), Variable("operation")}},
		},
	})
	require.NoError(t, err)

	b, err := builder.Build()
	require.NoError(t, err)

	v, err := b.Verify(root.Public())
	require.NoError(t, err)

	policy := Policy{Kind: PolicyKindAllow, Queries: []Rule{
		{
			Head: Predicate{Name: "allow_read"},
			Body: []Predicate{
				{Name: "right", IDs: []Term{SymbolAuthority, Variable("file"), Variable("operation")}},
			},
			Expressions: []Expression{
				{
					Value{Term: Variable("operation")},
					Value{Term: String("read")},
					BinaryEqual,
				},
			},
		},
	}}

	v.AddPolicy(policy)
	v.AddFact(Fact{Predicate: Predicate{
		Name: "operation",
		IDs:  []Term{Symbol("ambient"), String("read")},
	}})
	v.AddFact(Fact{Predicate: Predicate{
		Name: "resource",
		IDs:  []Term{Symbol("ambient"), String("some_file.txt")},
	}})

	require.NoError(t, v.Verify())

	v.Reset()
	v.AddPolicy(policy)
	v.AddFact(Fact{Predicate: Predicate{
		Name: "operation",
		IDs:  []Term{Symbol("ambient"), String("write")},
	}})
	v.AddFact(Fact{Predicate: Predicate{
		Name: "resource",
		IDs:  []Term{Symbol("ambient"), String("some_file.txt")},
	}})
	require.Equal(t, v.Verify(), ErrNoMatchingPolicy)
}

func TestVerifierSerializeLoad(t *testing.T) {
	rng := rand.Reader
	root := sig.GenerateKeypair(rng)

	builder := NewBuilder(root)
	b, err := builder.Build()
	require.NoError(t, err)

	v1, err := b.Verify(root.Public())
	require.NoError(t, err)

	policy := Policy{Kind: PolicyKindAllow, Queries: []Rule{
		{
			Head: Predicate{Name: "allow_read", IDs: []Term{Variable("file"), Variable("operation")}},
			Body: []Predicate{
				{Name: "right", IDs: []Term{SymbolAuthority, Variable("file"), Variable("operation")}},
			},
			Expressions: []Expression{
				{
					Value{Term: Variable("operation")},
					Value{Term: String("read")},
					BinaryEqual,
				},
			},
		},
	}}

	fact1 := Fact{Predicate: Predicate{
		Name: "operation",
		IDs:  []Term{Symbol("ambient"), String("read")},
	}}
	fact2 := Fact{Predicate: Predicate{
		Name: "resource",
		IDs:  []Term{Symbol("ambient"), String("some_file.txt")},
	}}
	rule1 := Rule{
		Head: Predicate{Name: "rule1", IDs: []Term{Variable("test")}},
		Body: []Predicate{
			{Name: "resource", IDs: []Term{Symbol("ambient"), String("some_file.txt")}},
		},
		Expressions: []Expression{
			{Value{Term: Integer(1)}, Value{Term: Integer(2)}, BinaryLessThan},
		},
	}
	check1 := Check{Queries: []Rule{rule1}}

	v1.AddFact(fact1)
	v1.AddFact(fact2)
	v1.AddRule(rule1)
	v1.AddCheck(check1)
	v1.AddPolicy(policy)
	s, err := v1.SerializePolicies()
	require.NoError(t, err)

	v2, err := b.Verify(root.Public())
	require.NoError(t, err)

	require.NoError(t, v2.LoadPolicies(s))

	require.Equal(t, v1.(*verifier).world.Facts(), v2.(*verifier).world.Facts())
	require.Equal(t, v1.(*verifier).world.Rules(), v2.(*verifier).world.Rules())
	require.Equal(t, v1.(*verifier).checks, v2.(*verifier).checks)
	require.Equal(t, v1.(*verifier).policies, v2.(*verifier).policies)
}
