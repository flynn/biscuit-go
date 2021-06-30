package biscuit

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/biscuit-auth/biscuit-go/datalog"
	"github.com/biscuit-auth/biscuit-go/pb"
	"github.com/biscuit-auth/biscuit-go/sig"
	"google.golang.org/protobuf/proto"
)

var (
	ErrDuplicateFact     = errors.New("biscuit: fact already exists")
	ErrInvalidBlockIndex = errors.New("biscuit: invalid block index")
)

type Builder interface {
	AddAuthorityFact(fact Fact) error
	AddAuthorityRule(rule Rule) error
	AddAuthorityCheck(check Check) error
	Build() (*Biscuit, error)
}

type builder struct {
	rng  io.Reader
	root sig.Keypair

	symbolsStart int
	symbols      *datalog.SymbolTable
	facts        *datalog.FactSet
	rules        []datalog.Rule
	checks       []datalog.Check
	context      string
}

type builderOption func(b *builder)

func WihtRandom(rng io.Reader) builderOption {
	return func(b *builder) {
		b.rng = rng
	}
}

func WithSymbols(symbols *datalog.SymbolTable) builderOption {
	return func(b *builder) {
		b.symbolsStart = symbols.Len()
		b.symbols = symbols.Clone()
	}
}

func NewBuilder(root sig.Keypair, opts ...builderOption) Builder {
	b := &builder{
		rng:          rand.Reader,
		root:         root,
		symbols:      defaultSymbolTable.Clone(),
		symbolsStart: defaultSymbolTable.Len(),
		facts:        new(datalog.FactSet),
	}

	for _, o := range opts {
		o(b)
	}

	return b
}

func (b *builder) AddAuthorityFact(fact Fact) error {
	if len(fact.Predicate.IDs) == 0 {
		fact.Predicate.IDs = []Term{SymbolAuthority}
	} else if fact.Predicate.IDs[0] != SymbolAuthority {
		terms := make([]Term, 1, len(fact.Predicate.IDs)+1)
		terms[0] = SymbolAuthority
		fact.Predicate.IDs = append(terms, fact.Predicate.IDs...)
	}

	dlFact := fact.convert(b.symbols)
	if !b.facts.Insert(dlFact) {
		return ErrDuplicateFact
	}

	return nil
}

func (b *builder) AddAuthorityRule(rule Rule) error {
	if len(rule.Head.IDs) == 0 {
		rule.Head.IDs = []Term{SymbolAuthority}
	} else if rule.Head.IDs[0] != SymbolAuthority {
		terms := make([]Term, 1, len(rule.Head.IDs)+1)
		terms[0] = SymbolAuthority
		rule.Head.IDs = append(terms, rule.Head.IDs...)
	}

	dlRule := rule.convert(b.symbols)
	b.rules = append(b.rules, dlRule)
	return nil
}

func (b *builder) AddAuthorityCheck(check Check) error {
	b.checks = append(b.checks, check.convert(b.symbols))
	return nil
}

func (b *builder) Build() (*Biscuit, error) {
	return New(b.rng, b.root, b.symbols, &Block{
		index:   0,
		symbols: b.symbols.SplitOff(b.symbolsStart),
		facts:   b.facts,
		rules:   b.rules,
		checks:  b.checks,
		context: b.context,
		version: MaxSchemaVersion,
	})
}

type Unmarshaler struct {
	Symbols *datalog.SymbolTable
}

func Unmarshal(serialized []byte) (*Biscuit, error) {
	return (&Unmarshaler{Symbols: defaultSymbolTable.Clone()}).Unmarshal(serialized)
}

func (u *Unmarshaler) Unmarshal(serialized []byte) (*Biscuit, error) {
	if u.Symbols == nil {
		return nil, errors.New("biscuit: unmarshaler requires a symbol table")
	}

	symbols := u.Symbols.Clone()

	container := new(pb.Biscuit)
	if err := proto.Unmarshal(serialized, container); err != nil {
		return nil, err
	}

	pbAuthority := new(pb.Block)
	if err := proto.Unmarshal(container.Authority, pbAuthority); err != nil {
		return nil, err
	}

	signature, err := protoSignatureToTokenSignature(container.Signature)
	if err != nil {
		return nil, err
	}

	pubKeys := make([]sig.PublicKey, len(container.Keys))
	for i, pk := range container.Keys {
		pubKey, err := sig.NewPublicKey(pk)
		if err != nil {
			return nil, err
		}
		pubKeys[i] = pubKey
	}

	signedBlocks := make([][]byte, 0, len(container.Blocks)+1)
	signedBlocks = append(signedBlocks, container.Authority)
	signedBlocks = append(signedBlocks, container.Blocks...)
	if err := signature.Verify(pubKeys, signedBlocks); err != nil {
		return nil, err
	}

	authority, err := protoBlockToTokenBlock(pbAuthority)
	if err != nil {
		return nil, err
	}
	if authority.index != 0 {
		return nil, ErrInvalidAuthorityIndex
	}
	symbols.Extend(authority.symbols)

	blocks := make([]*Block, len(container.Blocks))
	for i, sb := range container.Blocks {
		pbBlock := new(pb.Block)
		if err := proto.Unmarshal(sb, pbBlock); err != nil {
			return nil, err
		}

		if int(pbBlock.Index) != i+1 {
			return nil, ErrInvalidBlockIndex
		}

		block, err := protoBlockToTokenBlock(pbBlock)
		if err != nil {
			return nil, err
		}
		blocks[i] = block
		symbols.Extend(blocks[i].symbols)
	}

	return &Biscuit{
		authority: authority,
		symbols:   symbols,
		blocks:    blocks,
		container: container,
	}, nil
}

type BlockBuilder interface {
	AddFact(fact Fact) error
	AddRule(rule Rule) error
	AddCheck(check Check) error
	SetContext(string)
	Build() *Block
}

type blockBuilder struct {
	index        uint32
	symbolsStart int
	symbols      *datalog.SymbolTable
	facts        *datalog.FactSet
	rules        []datalog.Rule
	checks       []datalog.Check
	context      string
}

var _ BlockBuilder = (*blockBuilder)(nil)

func NewBlockBuilder(index uint32, baseSymbols *datalog.SymbolTable) BlockBuilder {
	return &blockBuilder{
		index:        index,
		symbolsStart: baseSymbols.Len(),
		symbols:      baseSymbols,
		facts:        new(datalog.FactSet),
	}
}

func (b *blockBuilder) AddFact(fact Fact) error {
	dlFact := fact.convert(b.symbols)
	if !b.facts.Insert(dlFact) {
		return ErrDuplicateFact
	}

	return nil
}

func (b *blockBuilder) AddRule(rule Rule) error {
	dlRule := rule.convert(b.symbols)
	b.rules = append(b.rules, dlRule)

	return nil
}

func (b *blockBuilder) AddCheck(check Check) error {
	dlCheck := check.convert(b.symbols)
	b.checks = append(b.checks, dlCheck)

	return nil
}

func (b *blockBuilder) SetContext(context string) {
	b.context = context
}

func (b *blockBuilder) Build() *Block {
	b.symbols = b.symbols.SplitOff(b.symbolsStart)

	facts := make(datalog.FactSet, len(*b.facts))
	copy(facts, *b.facts)

	rules := make([]datalog.Rule, len(b.rules))
	copy(rules, b.rules)

	checks := make([]datalog.Check, len(b.checks))
	copy(checks, b.checks)

	return &Block{
		index:   b.index,
		symbols: b.symbols.Clone(),
		facts:   &facts,
		rules:   rules,
		checks:  checks,
		context: b.context,
		version: MaxSchemaVersion,
	}
}
