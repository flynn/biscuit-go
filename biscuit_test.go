package biscuit

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/biscuit-auth/biscuit-go/datalog"
	"github.com/biscuit-auth/biscuit-go/sig"
	"github.com/stretchr/testify/require"
)

func TestBiscuit(t *testing.T) {
	rng := rand.Reader
	root := sig.GenerateKeypair(rng)

	builder := NewBuilder(root)

	builder.AddAuthorityFact(Fact{
		Predicate: Predicate{Name: "right", IDs: []Term{SymbolAuthority, String("/a/file1"), Symbol("read")}},
	})
	builder.AddAuthorityFact(Fact{
		Predicate: Predicate{Name: "right", IDs: []Term{SymbolAuthority, String("/a/file1"), Symbol("write")}},
	})
	builder.AddAuthorityFact(Fact{
		Predicate: Predicate{Name: "right", IDs: []Term{SymbolAuthority, String("/a/file2"), Symbol("read")}},
	})

	b1, err := builder.Build()
	require.NoError(t, err)

	b1ser, err := b1.Serialize()
	require.NoError(t, err)
	require.NotEmpty(t, b1ser)

	b1deser, err := Unmarshal(b1ser)
	require.NoError(t, err)

	block2 := b1deser.CreateBlock()
	block2.AddCheck(Check{
		Queries: []Rule{
			{
				Head: Predicate{Name: "caveat", IDs: []Term{Variable("0")}},
				Body: []Predicate{
					{Name: "resource", IDs: []Term{SymbolAmbient, Variable("0")}},
					{Name: "operation", IDs: []Term{SymbolAmbient, Symbol("read")}},
					{Name: "right", IDs: []Term{SymbolAuthority, Variable("0"), Symbol("read")}},
				},
			},
		},
	})

	keypair2 := sig.GenerateKeypair(rng)
	b2, err := b1deser.Append(rng, keypair2, block2.Build())
	require.NoError(t, err)

	b2ser, err := b2.Serialize()
	require.NoError(t, err)
	require.NotEmpty(t, b2ser)

	b2deser, err := Unmarshal(b2ser)
	require.NoError(t, err)

	block3 := b2deser.CreateBlock()
	block3.AddCheck(Check{
		Queries: []Rule{
			{
				Head: Predicate{Name: "caveat2", IDs: []Term{String("/a/file1")}},
				Body: []Predicate{
					{Name: "resource", IDs: []Term{SymbolAmbient, String("/a/file1")}},
				},
			},
		},
	})

	keypair3 := sig.GenerateKeypair(rng)
	b3, err := b2deser.Append(rng, keypair3, block3.Build())
	require.NoError(t, err)

	b3ser, err := b3.Serialize()
	require.NoError(t, err)
	require.NotEmpty(t, b3ser)

	b3deser, err := Unmarshal(b3ser)
	require.NoError(t, err)

	v3, err := b3deser.Verify(root.Public())
	require.NoError(t, err)

	v3.AddFact(Fact{Predicate: Predicate{Name: "resource", IDs: []Term{SymbolAmbient, String("/a/file1")}}})
	v3.AddFact(Fact{Predicate: Predicate{Name: "operation", IDs: []Term{SymbolAmbient, Symbol("read")}}})
	v3.AddPolicy(DefaultAllowPolicy)
	require.NoError(t, v3.Verify())

	v3.Reset()
	v3.AddFact(Fact{Predicate: Predicate{Name: "resource", IDs: []Term{SymbolAmbient, Symbol("/a/file2")}}})
	v3.AddFact(Fact{Predicate: Predicate{Name: "operation", IDs: []Term{SymbolAmbient, Symbol("read")}}})
	v3.AddPolicy(DefaultAllowPolicy)
	require.Error(t, v3.Verify())

	v3.Reset()
	v3.AddFact(Fact{Predicate: Predicate{Name: "resource", IDs: []Term{SymbolAmbient, Symbol("/a/file1")}}})
	v3.AddFact(Fact{Predicate: Predicate{Name: "operation", IDs: []Term{SymbolAmbient, Symbol("write")}}})
	v3.AddPolicy(DefaultAllowPolicy)
	require.Error(t, v3.Verify())
}

func TestBiscuitRules(t *testing.T) {
	rng := rand.Reader
	root := sig.GenerateKeypair(rng)

	builder := NewBuilder(root)

	builder.AddAuthorityRule(Rule{
		Head: Predicate{Name: "right", IDs: []Term{Variable("1"), Symbol("read")}},
		Body: []Predicate{
			{Name: "resource", IDs: []Term{SymbolAmbient, Variable("1")}},
			{Name: "owner", IDs: []Term{SymbolAmbient, Variable("0"), Variable("1")}},
		},
	})
	builder.AddAuthorityRule(Rule{
		Head: Predicate{Name: "right", IDs: []Term{Variable("1"), Symbol("write")}},
		Body: []Predicate{
			{Name: "resource", IDs: []Term{SymbolAmbient, Variable("1")}},
			{Name: "owner", IDs: []Term{SymbolAmbient, Variable("0"), Variable("1")}},
		},
	})
	builder.AddAuthorityCheck(Check{Queries: []Rule{
		{
			Head: Predicate{Name: "allowed_users", IDs: []Term{Variable("0")}},
			Body: []Predicate{
				{Name: "owner", IDs: []Term{SymbolAmbient, Variable("0"), Variable("1")}},
			},
			Expressions: []Expression{
				{
					Value{Set{Symbol("alice"), Symbol("bob")}},
					Value{Variable("0")},
					BinaryContains,
				},
			},
		},
	}})

	b1, err := builder.Build()
	require.NoError(t, err)

	// b1 should allow alice & bob only
	v, err := b1.Verify(root.Public())
	require.NoError(t, err)
	verifyOwner(t, v, map[string]bool{"alice": true, "bob": true, "eve": false})

	block := b1.CreateBlock()
	block.AddCheck(Check{
		Queries: []Rule{
			{
				Head: Predicate{Name: "caveat1", IDs: []Term{Variable("0"), Variable("1")}},
				Body: []Predicate{
					{Name: "right", IDs: []Term{SymbolAuthority, Variable("0"), Variable("1")}},
					{Name: "resource", IDs: []Term{SymbolAmbient, Variable("0")}},
					{Name: "operation", IDs: []Term{SymbolAmbient, Variable("1")}},
				},
			},
		},
	})
	block.AddCheck(Check{
		Queries: []Rule{
			{
				Head: Predicate{Name: "caveat2", IDs: []Term{Variable("0")}},
				Body: []Predicate{
					{Name: "resource", IDs: []Term{SymbolAmbient, Variable("0")}},
					{Name: "owner", IDs: []Term{SymbolAmbient, Symbol("alice"), Variable("0")}},
				},
			},
		},
	})

	b2, err := b1.Append(rng, sig.GenerateKeypair(rng), block.Build())
	require.NoError(t, err)

	// b2 should now only allow alice
	v, err = b2.Verify(root.Public())
	require.NoError(t, err)
	verifyOwner(t, v, map[string]bool{"alice": true, "bob": false, "eve": false})
}

func verifyOwner(t *testing.T, v Verifier, owners map[string]bool) {
	for user, valid := range owners {
		t.Run(fmt.Sprintf("verify owner %s", user), func(t *testing.T) {
			v.AddFact(Fact{Predicate: Predicate{Name: "resource", IDs: []Term{SymbolAmbient, String("file1")}}})
			v.AddFact(Fact{Predicate: Predicate{Name: "operation", IDs: []Term{SymbolAmbient, Symbol("write")}}})
			v.AddFact(Fact{
				Predicate: Predicate{
					Name: "owner",
					IDs: []Term{
						SymbolAmbient,
						Symbol(user),
						String("file1"),
					},
				},
			})
			v.AddPolicy(DefaultAllowPolicy)

			if valid {
				require.NoError(t, v.Verify())
			} else {
				require.Error(t, v.Verify())
			}
			v.Reset()
		})
	}
}

func TestCheckRootKey(t *testing.T) {
	rng := rand.Reader
	root := sig.GenerateKeypair(rng)

	builder := NewBuilder(root)

	b, err := builder.Build()
	require.NoError(t, err)

	require.NoError(t, b.checkRootKey(root.Public()))

	notRoot := sig.GenerateKeypair(rng)
	require.Equal(t, ErrUnknownPublicKey, b.checkRootKey(notRoot.Public()))

	b.container.Keys = [][]byte{}
	require.Equal(t, ErrEmptyKeys, b.checkRootKey(notRoot.Public()))
}

func TestGenerateWorld(t *testing.T) {
	rng := rand.Reader
	root := sig.GenerateKeypair(rng)

	build := NewBuilder(root)

	authorityFact1 := Fact{Predicate: Predicate{Name: "fact1", IDs: []Term{SymbolAuthority, String("file1")}}}
	authorityFact2 := Fact{Predicate: Predicate{Name: "fact2", IDs: []Term{SymbolAuthority, String("file2")}}}

	authorityRule1 := Rule{
		Head: Predicate{Name: "right", IDs: []Term{SymbolAuthority, Variable("1"), Symbol("read")}},
		Body: []Predicate{
			{Name: "resource", IDs: []Term{SymbolAmbient, Variable("1")}},
			{Name: "owner", IDs: []Term{SymbolAmbient, Variable("0"), Variable("1")}},
		},
	}
	authorityRule2 := Rule{
		Head: Predicate{Name: "right", IDs: []Term{SymbolAuthority, Variable("1"), Symbol("write")}},
		Body: []Predicate{
			{Name: "resource", IDs: []Term{SymbolAmbient, Variable("1")}},
			{Name: "owner", IDs: []Term{SymbolAmbient, Variable("0"), Variable("1")}},
		},
	}

	build.AddAuthorityFact(authorityFact1)
	build.AddAuthorityFact(authorityFact2)
	build.AddAuthorityRule(authorityRule1)
	build.AddAuthorityRule(authorityRule2)

	b, err := build.Build()
	require.NoError(t, err)

	symbolTable := (build.(*builder)).symbols
	world, err := b.generateWorld(defaultSymbolTable.Clone())
	require.NoError(t, err)

	expectedWorld := datalog.NewWorld()
	expectedWorld.AddFact(authorityFact1.convert(symbolTable))
	expectedWorld.AddFact(authorityFact2.convert(symbolTable))
	expectedWorld.AddRule(authorityRule1.convert(symbolTable))
	expectedWorld.AddRule(authorityRule2.convert(symbolTable))
	require.Equal(t, expectedWorld, world)

	blockBuild := b.CreateBlock()
	blockRule := Rule{
		Head: Predicate{Name: "blockRule", IDs: []Term{Variable("1")}},
		Body: []Predicate{
			{Name: "resource", IDs: []Term{SymbolAmbient, Variable("1")}},
			{Name: "owner", IDs: []Term{SymbolAmbient, Symbol("alice"), Variable("1")}},
		},
	}
	blockBuild.AddRule(blockRule)

	blockFact := Fact{Predicate{Name: "resource", IDs: []Term{String("file1")}}}
	blockBuild.AddFact(blockFact)

	b2, err := b.Append(rng, sig.GenerateKeypair(rng), blockBuild.Build())
	require.NoError(t, err)

	allSymbols := append(*symbolTable, *(blockBuild.(*blockBuilder)).symbols...)
	world, err = b2.generateWorld(&allSymbols)
	require.NoError(t, err)

	expectedWorld = datalog.NewWorld()
	expectedWorld.AddFact(authorityFact1.convert(&allSymbols))
	expectedWorld.AddFact(authorityFact2.convert(&allSymbols))
	expectedWorld.AddFact(blockFact.convert(&allSymbols))
	expectedWorld.AddRule(authorityRule1.convert(&allSymbols))
	expectedWorld.AddRule(authorityRule2.convert(&allSymbols))
	expectedWorld.AddRuleWithForbiddenIDs(
		blockRule.convert(&allSymbols),
		allSymbols.Sym(string(SymbolAuthority)),
		allSymbols.Sym(string(SymbolAmbient)),
	)
	require.Equal(t, expectedWorld, world)
}

func TestGenerateWorldErrors(t *testing.T) {
	testCases := []struct {
		Desc       string
		Symbols    *datalog.SymbolTable
		Facts      []Fact
		BlockFacts []Fact
		BlockRules []Rule
	}{
		{
			Desc:    "missing authority symbol",
			Symbols: &datalog.SymbolTable{},
		},
		{
			Desc:    "missing ambient symbol",
			Symbols: &datalog.SymbolTable{"authority"},
		},
		{
			Desc:    "invalid ambient authority fact",
			Symbols: &datalog.SymbolTable{"authority", "ambient"},
			Facts: []Fact{
				{Predicate: Predicate{Name: "test", IDs: []Term{SymbolAmbient, Variable("0")}}},
			},
		},
		{
			Desc:    "empty authority fact",
			Symbols: &datalog.SymbolTable{"authority", "ambient"},
			Facts: []Fact{
				{Predicate: Predicate{Name: "test", IDs: []Term{}}},
			},
		},
		{
			Desc:    "invalid block fact authority",
			Symbols: &datalog.SymbolTable{"authority", "ambient"},
			BlockFacts: []Fact{
				{Predicate: Predicate{Name: "test", IDs: []Term{SymbolAuthority, Variable("0")}}},
			},
		},
		{
			Desc:    "invalid block fact ambient",
			Symbols: &datalog.SymbolTable{"authority", "ambient"},
			BlockFacts: []Fact{
				{Predicate: Predicate{Name: "test", IDs: []Term{SymbolAmbient, Variable("0")}}},
			},
		},
		{
			Desc:    "invalid block fact empty",
			Symbols: &datalog.SymbolTable{"authority", "ambient"},
			BlockFacts: []Fact{
				{Predicate: Predicate{Name: "test", IDs: []Term{}}},
			},
		},
		{
			Desc:    "invalid block rule authority",
			Symbols: &datalog.SymbolTable{"authority", "ambient"},
			BlockRules: []Rule{
				{Head: Predicate{Name: "test", IDs: []Term{SymbolAuthority}}},
			},
		},
		{
			Desc:    "invalid block rule ambient",
			Symbols: &datalog.SymbolTable{"authority", "ambient"},
			BlockRules: []Rule{
				{Head: Predicate{Name: "test", IDs: []Term{SymbolAmbient}}},
			},
		},
		{
			Desc:    "invalid block rule empty",
			Symbols: &datalog.SymbolTable{"authority", "ambient"},
			BlockRules: []Rule{
				{Head: Predicate{Name: "test", IDs: []Term{}}},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			rng := rand.Reader
			root := sig.GenerateKeypair(rng)

			builder := NewBuilder(root)
			b, err := builder.Build()
			require.NoError(t, err)

			facts := make(datalog.FactSet, 0, len(testCase.Facts))
			for _, f := range testCase.Facts {
				facts = append(facts, f.convert(testCase.Symbols))
			}
			b.authority.facts = &facts

			blockFacts := make(datalog.FactSet, 0, len(testCase.BlockFacts))
			for _, f := range testCase.BlockFacts {
				blockFacts = append(blockFacts, f.convert(testCase.Symbols))
			}

			blockRules := make([]datalog.Rule, 0, len(testCase.BlockRules))
			for _, r := range testCase.BlockRules {
				blockRules = append(blockRules, r.convert(testCase.Symbols))
			}

			b.blocks = []*Block{{
				facts: &blockFacts,
				rules: blockRules,
			}}

			_, err = b.generateWorld(testCase.Symbols)
			require.Error(t, err)
		})
	}
}

func TestAppendErrors(t *testing.T) {
	rng := rand.Reader
	builder := NewBuilder(sig.GenerateKeypair(rng))

	t.Run("symbols overlap", func(t *testing.T) {
		b, err := builder.Build()
		require.NoError(t, err)

		_, err = b.Append(rng, sig.GenerateKeypair(rng), &Block{
			symbols: &datalog.SymbolTable{"authority"},
		})
		require.Equal(t, ErrSymbolTableOverlap, err)
	})

	t.Run("invalid block index", func(t *testing.T) {
		b, err := builder.Build()
		require.NoError(t, err)

		_, err = b.Append(rng, sig.GenerateKeypair(rng), &Block{
			symbols: &datalog.SymbolTable{},
			index:   2,
		})
		require.Equal(t, ErrInvalidBlockIndex, err)
	})

	t.Run("biscuit is sealed", func(t *testing.T) {
		b, err := builder.Build()
		require.NoError(t, err)
		_, err = b.Append(rng, sig.GenerateKeypair(rng), &Block{
			symbols: &datalog.SymbolTable{},
			facts:   &datalog.FactSet{},
			index:   1,
		})
		require.NoError(t, err)

		b.container = nil
		_, err = b.Append(rng, sig.GenerateKeypair(rng), &Block{
			symbols: &datalog.SymbolTable{},
			index:   1,
		})
		require.Error(t, err)
	})
}

func TestNewErrors(t *testing.T) {
	rng := rand.Reader

	t.Run("authority block symbols overlap", func(t *testing.T) {
		_, err := New(rng, sig.GenerateKeypair(rng), &datalog.SymbolTable{"symbol1", "symbol2"}, &Block{
			symbols: &datalog.SymbolTable{"symbol1"},
		})
		require.Equal(t, ErrSymbolTableOverlap, err)
	})

	t.Run("invalid authority block index", func(t *testing.T) {
		_, err := New(rng, sig.GenerateKeypair(rng), &datalog.SymbolTable{"symbol1", "symbol2"}, &Block{
			symbols: &datalog.SymbolTable{"symbol3"},
			index:   1,
		})
		require.Equal(t, ErrInvalidAuthorityIndex, err)
	})
}

func TestBiscuitVerifyErrors(t *testing.T) {
	rng := rand.Reader
	root := sig.GenerateKeypair(rng)

	builder := NewBuilder(root)
	b, err := builder.Build()
	require.NoError(t, err)

	_, err = b.Verify(root.Public())
	require.NoError(t, err)

	_, err = b.Verify(sig.GenerateKeypair(rng).Public())
	require.Error(t, err)
}

func TestBiscuitSha256Sum(t *testing.T) {
	rng := rand.Reader
	root := sig.GenerateKeypair(rng)

	builder := NewBuilder(root)
	b, err := builder.Build()
	require.NoError(t, err)

	require.Equal(t, 0, b.BlockCount())
	h0, err := b.SHA256Sum(0)
	require.NoError(t, err)
	require.NotEmpty(t, h0)

	_, err = b.SHA256Sum(1)
	require.Error(t, err)
	_, err = b.SHA256Sum(-1)
	require.Error(t, err)

	blockBuilder := b.CreateBlock()
	b, err = b.Append(rng, root, blockBuilder.Build())
	require.NoError(t, err)
	require.Equal(t, 1, b.BlockCount())

	h10, err := b.SHA256Sum(0)
	require.NoError(t, err)
	require.Equal(t, h0, h10)
	h11, err := b.SHA256Sum(1)
	require.NoError(t, err)
	require.NotEmpty(t, h11)

	blockBuilder = b.CreateBlock()
	b, err = b.Append(rng, root, blockBuilder.Build())
	require.NoError(t, err)
	require.Equal(t, 2, b.BlockCount())

	h20, err := b.SHA256Sum(0)
	require.NoError(t, err)
	require.Equal(t, h0, h20)
	h21, err := b.SHA256Sum(1)
	require.NoError(t, err)
	require.Equal(t, h11, h21)
	h22, err := b.SHA256Sum(2)
	require.NoError(t, err)
	require.NotEmpty(t, h22)
}

func TestGetBlockID(t *testing.T) {
	rng := rand.Reader
	root := sig.GenerateKeypair(rng)
	builder := NewBuilder(root)

	// add 3 facts authority_0_fact_{0,1,2} in authority block
	for i := 0; i < 3; i++ {
		require.NoError(t, builder.AddAuthorityFact(Fact{Predicate: Predicate{
			Name: fmt.Sprintf("authority_0_fact_%d", i),
			IDs:  []Term{Integer(i)},
		}}))
	}

	b, err := builder.Build()
	require.NoError(t, err)
	// add 2 extra blocks each containing 3 facts block_{0,1}_fact_{0,1,2}
	for i := 0; i < 2; i++ {
		blockBuilder := b.CreateBlock()
		for j := 0; j < 3; j++ {
			blockBuilder.AddFact(Fact{Predicate: Predicate{
				Name: fmt.Sprintf("block_%d_fact_%d", i, j),
				IDs:  []Term{Symbol("block"), Integer(i), Integer(j)},
			}})
		}
		b, err = b.Append(rng, sig.GenerateKeypair(rng), blockBuilder.Build())
		require.NoError(t, err)
	}

	idx, err := b.GetBlockID(Fact{Predicate{
		Name: "authority_0_fact_0",
		IDs:  []Term{SymbolAuthority, Integer(0)},
	}})
	require.NoError(t, err)
	require.Equal(t, 0, idx)
	idx, err = b.GetBlockID(Fact{Predicate{
		Name: "authority_0_fact_2",
		IDs:  []Term{SymbolAuthority, Integer(2)},
	}})
	require.NoError(t, err)
	require.Equal(t, 0, idx)

	idx, err = b.GetBlockID(Fact{Predicate{
		Name: "block_0_fact_2",
		IDs:  []Term{Symbol("block"), Integer(0), Integer(2)},
	}})
	require.NoError(t, err)
	require.Equal(t, 1, idx)
	idx, err = b.GetBlockID(Fact{Predicate{
		Name: "block_1_fact_1",
		IDs:  []Term{Symbol("block"), Integer(1), Integer(1)},
	}})
	require.NoError(t, err)
	require.Equal(t, 2, idx)

	_, err = b.GetBlockID(Fact{Predicate{
		Name: "block_1_fact_3",
		IDs:  []Term{Symbol("block"), Integer(1), Integer(3)},
	}})
	require.Equal(t, ErrFactNotFound, err)
	_, err = b.GetBlockID(Fact{Predicate{
		Name: "block_2_fact_1",
		IDs:  []Term{Symbol("block"), Integer(2), Integer(1)},
	}})
	require.Equal(t, ErrFactNotFound, err)
	_, err = b.GetBlockID(Fact{Predicate{
		Name: "block_1_fact_1",
		IDs:  []Term{Integer(1), Integer(1)},
	}})
	require.Equal(t, ErrFactNotFound, err)
}

func TestInvalidRuleGeneration(t *testing.T) {
	rng := rand.Reader
	root := sig.GenerateKeypair(rng)
	builder := NewBuilder(root)
	builder.AddAuthorityCheck(Check{Queries: []Rule{
		{
			Head: Predicate{Name: "check1"},
			Body: []Predicate{
				{Name: "operation", IDs: []Term{SymbolAmbient, Symbol("read")}},
			},
		},
	}})

	b, err := builder.Build()
	require.NoError(t, err)
	t.Log(b.String())

	blockBuilder := b.CreateBlock()
	blockBuilder.AddRule(Rule{
		Head: Predicate{Name: "operation", IDs: []Term{Variable("sym"), Symbol("read")}},
		Body: []Predicate{
			{Name: "operation", IDs: []Term{Variable("sym"), Variable("operation")}},
		},
	})

	block := blockBuilder.Build()
	b, err = b.Append(rng, sig.GenerateKeypair(rng), block)
	require.NoError(t, err)
	t.Log(b.String())

	verifier, err := b.Verify(root.Public())
	require.NoError(t, err)

	verifier.AddFact(Fact{Predicate: Predicate{
		Name: "operation",
		IDs:  []Term{SymbolAmbient, Symbol("write")},
	}})

	err = verifier.Verify()
	t.Log(verifier.PrintWorld())
	require.Error(t, err)
}
