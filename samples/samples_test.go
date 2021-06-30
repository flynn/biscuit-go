package biscuittest

import (
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go"
	"github.com/biscuit-auth/biscuit-go/sig"
	"github.com/stretchr/testify/require"
)

type sampleVerifier struct {
	biscuit.Verifier
}

func (s *sampleVerifier) AddOperation(op string) {
	s.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "operation",
		IDs:  []biscuit.Term{biscuit.SymbolAmbient, biscuit.Symbol(op)}}},
	)
}

func (s *sampleVerifier) AddResource(res string) {
	s.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "resource",
		IDs:  []biscuit.Term{biscuit.SymbolAmbient, biscuit.String(res)}}},
	)
}

func (s *sampleVerifier) SetTime(t time.Time) {
	s.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "time",
		IDs:  []biscuit.Term{biscuit.SymbolAmbient, biscuit.Date(t)}}},
	)
}

var versions = []string{"v0", "v1"}

func TestSample1_Basic(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test1_basic.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			pubkey := loadRootPublicKey(t, v)

			v, err := b.Verify(pubkey)
			require.NoError(t, err)

			verifier := &sampleVerifier{v}

			verifier.AddOperation("read")
			verifier.AddResource("file1")
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, verifier.Verify())

			verifier.Reset()
			verifier.AddOperation("read")
			verifier.AddResource("file2")
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, verifier.Verify())

			verifier.Reset()
			verifier.AddOperation("write")
			verifier.AddResource("file1")
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.Error(t, verifier.Verify())

			s, err := b.Serialize()
			require.NoError(t, err)
			require.Equal(t, len(token), len(s))
		})
	}
}

func TestSample2_DifferentRootKey(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test2_different_root_key.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			v, err := b.Verify(loadRootPublicKey(t, v))
			require.Equal(t, biscuit.ErrUnknownPublicKey, err)
			require.Nil(t, v)
		})
	}
}

func TestSample3_InvalidSignatureFormat(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test3_invalid_signature_format.bc")

			b, err := biscuit.Unmarshal(token)
			require.Equal(t, sig.ErrInvalidZSize, err)
			require.Nil(t, b)
		})
	}
}

func TestSample4_RandomBlock(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test4_random_block.bc")

			_, err := biscuit.Unmarshal(token)
			require.Equal(t, sig.ErrInvalidSignature, err)
		})
	}
}

func TestSample5_InvalidSignature(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test5_invalid_signature.bc")

			b, err := biscuit.Unmarshal(token)
			require.Equal(t, sig.ErrInvalidSignature, err)
			require.Nil(t, b)
		})
	}
}

func TestSample6_ReorderedBlocks(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test6_reordered_blocks.bc")

			_, err := biscuit.Unmarshal(token)
			require.Equal(t, biscuit.ErrInvalidBlockIndex, err)
		})
	}
}

func TestSample7_InvalidBlockFactAuthority(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test7_invalid_block_fact_authority.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			_, err = b.Verify(loadRootPublicKey(t, v))
			require.Equal(t, biscuit.ErrInvalidBlockFact, err)
		})
	}
}

func TestSample8_InvalidBlockFactAmbient(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test8_invalid_block_fact_ambient.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			_, err = b.Verify(loadRootPublicKey(t, v))
			require.Equal(t, biscuit.ErrInvalidBlockFact, err)
		})
	}
}

func TestSample9_ExpiredToken(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test9_expired_token.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			v, err := b.Verify(loadRootPublicKey(t, v))
			require.NoError(t, err)

			verifier := &sampleVerifier{v}

			verifier.AddOperation("read")
			verifier.AddResource("file1")
			verifier.SetTime(time.Now())
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.Error(t, verifier.Verify())

			verifier.Reset()
			expireTime, err := time.Parse(time.RFC3339, "2018-12-20T01:00:00+01:00")
			require.NoError(t, err)

			verifier.AddOperation("read")
			verifier.AddResource("file1")
			verifier.SetTime(expireTime)
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, verifier.Verify())
		})
	}
}

func TestSample10_AuthorityRules(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test10_authority_rules.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			v, err := b.Verify(loadRootPublicKey(t, v))
			require.NoError(t, err)

			verifier := &sampleVerifier{v}

			verifier.AddOperation("read")
			verifier.AddResource("file1")
			verifier.AddFact(biscuit.Fact{
				Predicate: biscuit.Predicate{
					Name: "owner",
					IDs: []biscuit.Term{
						biscuit.SymbolAmbient,
						biscuit.Symbol("alice"),
						biscuit.String("file1"),
					},
				},
			})
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, verifier.Verify())

			verifier.Reset()
			verifier.AddOperation("write")
			verifier.AddResource("file1")
			verifier.AddFact(biscuit.Fact{
				Predicate: biscuit.Predicate{
					Name: "owner",
					IDs: []biscuit.Term{
						biscuit.SymbolAmbient,
						biscuit.Symbol("alice"),
						biscuit.String("file1"),
					},
				},
			})
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, verifier.Verify())

			verifier.Reset()
			verifier.AddOperation("read")
			verifier.AddOperation("write")
			verifier.AddResource("file1")
			verifier.AddFact(biscuit.Fact{
				Predicate: biscuit.Predicate{
					Name: "owner",
					IDs: []biscuit.Term{
						biscuit.SymbolAmbient,
						biscuit.Symbol("alice"),
						biscuit.String("file1"),
					},
				},
			})
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, verifier.Verify())

			verifier.Reset()
			verifier.AddOperation("delete")
			verifier.AddResource("file1")
			verifier.AddFact(biscuit.Fact{
				Predicate: biscuit.Predicate{
					Name: "owner",
					IDs: []biscuit.Term{
						biscuit.SymbolAmbient,
						biscuit.Symbol("alice"),
						biscuit.String("file1"),
					},
				},
			})
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.Error(t, verifier.Verify())
		})
	}
}

func TestSample11_VerifierAuthorityChecks(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test11_verifier_authority_caveats.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			v, err := b.Verify(loadRootPublicKey(t, v))
			require.NoError(t, err)

			verifierCheck := biscuit.Check{
				Queries: []biscuit.Rule{
					{
						Head: biscuit.Predicate{
							Name: "caveat1",
							IDs:  []biscuit.Term{biscuit.Variable("0"), biscuit.Variable("1")},
						},
						Body: []biscuit.Predicate{
							{Name: "right", IDs: []biscuit.Term{biscuit.Symbol("authority"), biscuit.Variable("0"), biscuit.Variable("1")}},
							{Name: "resource", IDs: []biscuit.Term{biscuit.SymbolAmbient, biscuit.Variable("0")}},
							{Name: "operation", IDs: []biscuit.Term{biscuit.SymbolAmbient, biscuit.Variable("1")}},
						},
					},
				},
			}

			verifier := &sampleVerifier{v}

			verifier.AddOperation("read")
			verifier.AddResource("file1")
			verifier.AddCheck(verifierCheck)
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, verifier.Verify())

			verifier.Reset()
			verifier.AddOperation("write")
			verifier.AddResource("file1")
			verifier.AddCheck(verifierCheck)
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.Error(t, verifier.Verify())

			verifier.Reset()
			verifier.AddOperation("read")
			verifier.AddResource("/another/file1")
			verifier.AddCheck(verifierCheck)
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.Error(t, verifier.Verify())
		})
	}
}

func TestSample12_AuthorityChecks(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test12_authority_caveats.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			v, err := b.Verify(loadRootPublicKey(t, v))
			require.NoError(t, err)

			verifier := &sampleVerifier{v}

			verifier.AddResource("file1")
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, verifier.Verify())

			verifier.AddResource("file1")
			verifier.AddOperation("anything")
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, verifier.Verify())

			verifier.Reset()
			verifier.AddResource("file2")
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.Error(t, verifier.Verify())
		})
	}
}

func TestSample13_BlockRules(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test13_block_rules.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			v, err := b.Verify(loadRootPublicKey(t, v))
			require.NoError(t, err)

			verifier := &sampleVerifier{v}

			verifier.AddResource("file1")
			verifier.SetTime(time.Now())
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, verifier.Verify())

			file1ValidTime, err := time.Parse(time.RFC3339, "2030-12-31T12:59:59+00:00")
			require.NoError(t, err)

			verifier.Reset()
			verifier.AddResource("file1")
			verifier.SetTime(file1ValidTime)
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, verifier.Verify())

			verifier.Reset()
			verifier.AddResource("file1")
			verifier.SetTime(file1ValidTime.Add(1 * time.Second))
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.Error(t, verifier.Verify())

			verifier.Reset()
			verifier.AddResource("file2")
			verifier.SetTime(time.Now())
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.Error(t, verifier.Verify())

			otherFileValidTime, err := time.Parse(time.RFC3339, "1999-12-31T12:59:59+00:00")
			require.NoError(t, err)

			verifier.Reset()
			verifier.AddResource("file2")
			verifier.SetTime(otherFileValidTime)
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, verifier.Verify())
		})
	}
}

func TestSample14_RegexConstraint(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test14_regex_constraint.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			v, err := b.Verify(loadRootPublicKey(t, v))
			require.NoError(t, err)

			verifier := &sampleVerifier{v}

			validFiles := []string{
				"file1.txt",
				"file1.txt.zip",
				"file9000.txt",
				"/dir/file000.txt",
				"file000.txt/dir/",
			}

			for _, validFile := range validFiles {
				verifier.Reset()
				verifier.AddResource(validFile)
				verifier.AddPolicy(biscuit.DefaultAllowPolicy)
				require.NoError(t, verifier.Verify())
			}

			invalidFiles := []string{
				"file1",
				"fileA.txt",
				"fileA1.txt",
				"file1.zip",
			}

			for _, invalidFile := range invalidFiles {
				verifier.Reset()
				verifier.AddResource(invalidFile)
				verifier.AddPolicy(biscuit.DefaultAllowPolicy)
				require.Error(t, verifier.Verify())
			}
		})
	}
}

func TestSample15_MultiQueriesChecks(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test15_multi_queries_caveats.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			v, err := b.Verify(loadRootPublicKey(t, v))
			require.NoError(t, err)

			rule1 := biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "test_must_be_present_authority",
					IDs:  []biscuit.Term{biscuit.Variable("0")},
				},
				Body: []biscuit.Predicate{
					{Name: "must_be_present", IDs: []biscuit.Term{biscuit.Symbol("authority"), biscuit.Variable("0")}},
				},
			}

			rule2 := biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "test_must_be_present",
					IDs:  []biscuit.Term{biscuit.Variable("0")},
				},
				Body: []biscuit.Predicate{
					{Name: "must_be_present", IDs: []biscuit.Term{biscuit.Variable("0")}},
				},
			}

			v.AddCheck(biscuit.Check{Queries: []biscuit.Rule{rule1, rule2}})
			v.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, v.Verify())

			v.Reset()
			v.AddCheck(biscuit.Check{Queries: []biscuit.Rule{rule1}})
			v.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, v.Verify())

			v.Reset()
			v.AddCheck(biscuit.Check{Queries: []biscuit.Rule{rule2}})
			v.AddPolicy(biscuit.DefaultAllowPolicy)
			require.Error(t, v.Verify())
		})
	}
}

func TestSample16_CheckHeadName(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test16_caveat_head_name.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			v, err := b.Verify(loadRootPublicKey(t, v))
			require.NoError(t, err)

			v.AddPolicy(biscuit.DefaultAllowPolicy)
			require.Error(t, v.Verify())

			v.Reset()
			v.AddFact(biscuit.Fact{
				Predicate: biscuit.Predicate{Name: "resource", IDs: []biscuit.Term{biscuit.SymbolAmbient, biscuit.Symbol("hello")}},
			})
			v.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, v.Verify())
		})
	}
}
func TestSample17_Expressions(t *testing.T) {
	t.Run("v1", func(t *testing.T) {
		token := loadSampleToken(t, "v1", "test17_expressions.bc")

		b, err := biscuit.Unmarshal(token)
		require.NoError(t, err)

		v, err := b.Verify(loadRootPublicKey(t, "v1"))
		require.NoError(t, err)

		v.AddPolicy(biscuit.DefaultAllowPolicy)
		require.NoError(t, v.Verify())
	})
}

func TestSample18_UnboundVariables(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test18_unbound_variables_in_rule.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			v, err := b.Verify(loadRootPublicKey(t, v))
			require.NoError(t, err)
			v.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: "operation",
				IDs:  []biscuit.Term{biscuit.SymbolAmbient, biscuit.Symbol("write")},
			}})
			require.Error(t, v.Verify())
		})
	}
}

func TestSample19_GeneratingAmbientFromVariables(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test19_generating_ambient_from_variables.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			t.Log(b.String())

			v, err := b.Verify(loadRootPublicKey(t, v))
			require.NoError(t, err)

			v.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: "operation",
				IDs:  []biscuit.Term{biscuit.SymbolAmbient, biscuit.Symbol("write")},
			}})
			require.Error(t, v.Verify())
		})
	}
}

func loadSampleToken(t *testing.T, version string, path string) []byte {
	token, err := ioutil.ReadFile(fmt.Sprintf("data/%s/%s", version, path))
	require.NoError(t, err)

	return token
}

func loadRootPublicKey(t *testing.T, version string) sig.PublicKey {
	pk, err := ioutil.ReadFile(fmt.Sprintf("data/%s/root_key.pub", version))
	require.NoError(t, err)
	pubkey, err := sig.NewPublicKey(pk)
	require.NoError(t, err)

	return pubkey
}
