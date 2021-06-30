package biscuit

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/biscuit-auth/biscuit-go/datalog"
	"github.com/biscuit-auth/biscuit-go/pb"
	"github.com/biscuit-auth/biscuit-go/sig"
	"google.golang.org/protobuf/proto"
)

// Biscuit represents a valid Biscuit token
// It contains multiple `Block` elements, the associated symbol table,
// and a serialized version of this data
type Biscuit struct {
	authority *Block
	blocks    []*Block
	symbols   *datalog.SymbolTable
	container *pb.Biscuit
}

var (
	// ErrSymbolTableOverlap is returned when multiple blocks declare the same symbols
	ErrSymbolTableOverlap = errors.New("biscuit: symbol table overlap")
	// ErrInvalidAuthorityIndex occurs when an authority block index is not 0
	ErrInvalidAuthorityIndex = errors.New("biscuit: invalid authority index")
	// ErrInvalidAuthorityFact occurs when an authority fact is an ambient fact
	ErrInvalidAuthorityFact = errors.New("biscuit: invalid authority fact")
	// ErrInvalidBlockFact occurs when a block fact provides an authority or ambient fact
	ErrInvalidBlockFact = errors.New("biscuit: invalid block fact")
	// ErrInvalidBlockRule occurs when a block rule generate an authority or ambient fact
	ErrInvalidBlockRule = errors.New("biscuit: invalid block rule")
	// ErrEmptyKeys is returned when verifying a biscuit having no keys
	ErrEmptyKeys = errors.New("biscuit: empty keys")
	// ErrUnknownPublicKey is returned when verifying a biscuit with the wrong public key
	ErrUnknownPublicKey = errors.New("biscuit: unknown public key")
)

func New(rng io.Reader, root sig.Keypair, baseSymbols *datalog.SymbolTable, authority *Block) (*Biscuit, error) {
	if rng == nil {
		rng = rand.Reader
	}

	symbols := baseSymbols.Clone()

	if !symbols.IsDisjoint(authority.symbols) {
		return nil, ErrSymbolTableOverlap
	}

	if authority.index != 0 {
		return nil, ErrInvalidAuthorityIndex
	}

	symbols.Extend(authority.symbols)

	protoAuthority, err := tokenBlockToProtoBlock(authority)
	if err != nil {
		return nil, err
	}
	marshalledAuthority, err := proto.Marshal(protoAuthority)
	if err != nil {
		return nil, err
	}

	ts := &sig.TokenSignature{}
	ts.Sign(rng, root, marshalledAuthority)

	container := &pb.Biscuit{
		Authority: marshalledAuthority,
		Keys:      [][]byte{root.Public().Bytes()},
		Signature: tokenSignatureToProtoSignature(ts),
	}

	return &Biscuit{
		authority: authority,
		symbols:   symbols,
		container: container,
	}, nil
}

func (b *Biscuit) CreateBlock() BlockBuilder {
	return NewBlockBuilder(uint32(len(b.blocks)+1), b.symbols.Clone())
}

func (b *Biscuit) Append(rng io.Reader, keypair sig.Keypair, block *Block) (*Biscuit, error) {
	if b.container == nil {
		return nil, errors.New("biscuit: append failed, token is sealed")
	}

	if !b.symbols.IsDisjoint(block.symbols) {
		return nil, ErrSymbolTableOverlap
	}

	if int(block.index) != len(b.blocks)+1 {
		return nil, ErrInvalidBlockIndex
	}

	// clone biscuit fields and append new block
	authority := new(Block)
	*authority = *b.authority

	blocks := make([]*Block, len(b.blocks)+1)
	for i, oldBlock := range b.blocks {
		blocks[i] = new(Block)
		*blocks[i] = *oldBlock
	}
	blocks[len(b.blocks)] = block

	symbols := b.symbols.Clone()
	symbols.Extend(block.symbols)

	// serialize and sign the new block
	protoBlock, err := tokenBlockToProtoBlock(block)
	if err != nil {
		return nil, err
	}
	marshalledBlock, err := proto.Marshal(protoBlock)
	if err != nil {
		return nil, err
	}

	ts, err := protoSignatureToTokenSignature(b.container.Signature)
	if err != nil {
		return nil, err
	}
	ts.Sign(rng, keypair, marshalledBlock)

	// clone container and append new marshalled block and public key
	container := &pb.Biscuit{
		Authority: append([]byte{}, b.container.Authority...),
		Blocks:    append([][]byte{}, b.container.Blocks...),
		Keys:      append([][]byte{}, b.container.Keys...),
		Signature: tokenSignatureToProtoSignature(ts),
	}

	container.Blocks = append(container.Blocks, marshalledBlock)
	container.Keys = append(container.Keys, keypair.Public().Bytes())

	return &Biscuit{
		authority: authority,
		blocks:    blocks,
		symbols:   symbols,
		container: container,
	}, nil
}

func (b *Biscuit) Verify(root sig.PublicKey) (Verifier, error) {
	if err := b.checkRootKey(root); err != nil {
		return nil, err
	}

	return NewVerifier(b)
}

func (b *Biscuit) Checks() [][]datalog.Check {
	result := make([][]datalog.Check, 0, len(b.blocks)+1)
	result = append(result, b.authority.checks)
	for _, block := range b.blocks {
		result = append(result, block.checks)
	}
	return result
}

func (b *Biscuit) Serialize() ([]byte, error) {
	return proto.Marshal(b.container)
}

var ErrFactNotFound = errors.New("biscuit: fact not found")

// GetBlockID returns the first block index containing a fact
// starting from the authority block and then each block in the order they were added.
// ErrFactNotFound is returned when no block contains the fact.
func (b *Biscuit) GetBlockID(fact Fact) (int, error) {
	// don't store symbols from searched fact in the verifier table
	symbols := b.symbols.Clone()
	datalogFact := fact.Predicate.convert(symbols)

	for _, f := range *b.authority.facts {
		if f.Equal(datalogFact) {
			return 0, nil
		}
	}

	for i, b := range b.blocks {
		for _, f := range *b.facts {
			if f.Equal(datalogFact) {
				return i + 1, nil
			}
		}
	}

	return 0, ErrFactNotFound
}

// SHA256Sum returns a hash of `count` biscuit blocks + the authority block
// along with their respective keys.
func (b *Biscuit) SHA256Sum(count int) ([]byte, error) {
	if count < 0 {
		return nil, fmt.Errorf("biscuit: invalid count,  %d < 0 ", count)
	}
	if g, w := count, len(b.container.Blocks); g > w {
		return nil, fmt.Errorf("biscuit: invalid count,  %d > %d", g, w)
	}

	h := sha256.New()
	// write the authority block and the root key
	if _, err := h.Write(b.container.Authority); err != nil {
		return nil, err
	}
	if _, err := h.Write(b.container.Keys[0]); err != nil {
		return nil, err
	}

	for _, block := range b.container.Blocks[:count] {
		if _, err := h.Write(block); err != nil {
			return nil, err
		}
	}
	for _, key := range b.container.Keys[:count+1] { // +1 to skip the root key
		if _, err := h.Write(key); err != nil {
			return nil, err
		}
	}

	return h.Sum(nil), nil
}

func (b *Biscuit) BlockCount() int {
	return len(b.container.Blocks)
}

func (b *Biscuit) String() string {
	blocks := make([]string, len(b.blocks))
	for i, block := range b.blocks {
		blocks[i] = block.String(b.symbols)
	}

	return fmt.Sprintf(`
Biscuit {
	symbols: %+q
	authority: %s
	blocks: %v
}`,
		*b.symbols,
		b.authority.String(b.symbols),
		blocks,
	)
}

func (b *Biscuit) checkRootKey(root sig.PublicKey) error {
	if len(b.container.Keys) == 0 {
		return ErrEmptyKeys
	}
	if !bytes.Equal(b.container.Keys[0], root.Bytes()) {
		return ErrUnknownPublicKey
	}

	return nil
}

func (b *Biscuit) generateWorld(symbols *datalog.SymbolTable) (*datalog.World, error) {
	world := datalog.NewWorld()

	idAuthority := symbols.Sym(string(SymbolAuthority))
	if idAuthority == nil {
		return nil, fmt.Errorf("biscuit: failed to generate world, missing %q symbol in symbol table", string(SymbolAuthority))
	}
	idAmbient := symbols.Sym(string(SymbolAmbient))
	if idAmbient == nil {
		return nil, fmt.Errorf("biscuit: failed to generate world, missing %q symbol in symbol table", string(SymbolAmbient))
	}

	for _, fact := range *b.authority.facts {
		if len(fact.Predicate.IDs) == 0 || fact.Predicate.IDs[0] == idAmbient {
			return nil, ErrInvalidAuthorityFact
		}

		world.AddFact(fact)
	}

	for _, rule := range b.authority.rules {
		world.AddRule(rule)
	}

	for _, block := range b.blocks {
		for _, fact := range *block.facts {
			if len(fact.Predicate.IDs) == 0 || fact.Predicate.IDs[0] == idAuthority || fact.Predicate.IDs[0] == idAmbient {
				return nil, ErrInvalidBlockFact
			}
			world.AddFact(fact)
		}

		for _, rule := range block.rules {
			// rule head cannot contains authority or ambient symbols
			if len(rule.Head.IDs) == 0 || rule.Head.IDs[0] == idAuthority || rule.Head.IDs[0] == idAmbient {
				return nil, ErrInvalidBlockRule
			}
			// and also ensure variables won't be replaced by authority and ambient Symbols at generation
			world.AddRuleWithForbiddenIDs(rule, idAuthority, idAmbient)
		}
	}

	if err := world.Run(); err != nil {
		return nil, err
	}

	return world, nil
}
