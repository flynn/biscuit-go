
# biscuit-go

biscuit-go is an implementation of [Biscuit](https://github.com/clevercloud/biscuit) in Go. It aims to be fully compatible with other existing implementations, so that tokens issued by, for example, the Rust version, could be validated by this library and vice versa.

## Documentation and specifications

- [CleverCloud/biscuit repository](https://github.com/CleverCloud/biscuit), for the latest documentation and specifications.
- [CleverCloud/biscuit-rust](https://github.com/clevercloud/biscuit-rust) for some more technical details.

## Usage

#### Create a biscuit
```go
rng := rand.Reader
root := sig.GenerateKeypair(rng)

// retrieve public key with root.Public()
// and share or expose it to verifiers

builder := biscuit.NewBuilder(root)

err := builder.AddAuthorityFact(biscuit.Fact{biscuit.Predicate{
    Name: "right",
    IDs: []biscuit.Term{
        biscuit.Symbol("authority"),
        biscuit.String("/a/file1.txt"),
        biscuit.Symbol("read"),
    },
}})
if err != nil {
    panic(fmt.Errorf("failed to add authority facts: %v", err))
}

// ... add more authority facts, rules, caveats...

b, err := builder.Build()
if err != nil {
    panic(fmt.Errorf("failed to build biscuit: %v", err))
}
token, err := b.Serialize()
if err != nil {
    panic(fmt.Errorf("failed to serialize biscuit: %v", err))
}

// token is now a []byte, ready to be shared
```

#### Attenuate a biscuit
```go
b, err = biscuit.Unmarshal(token)
if err != nil {
    panic(fmt.Errorf("failed to deserialize biscuit: %v", err))
}

// Attenuate the biscuit by appending a new block to it
blockBuilder := b.CreateBlock()
blockBuilder.AddFact(biscuit.Fact{/* ... */})

// ... add more facts, rules, caveats...

newKeyPair := sig.GenerateKeypair(rng)
attenuatedBiscuit, err := b.Append(rng, newKeyPair, blockBuilder.Build())
if err != nil {
    panic(fmt.Errorf("failed to append: %v", err))
}
attenuatedToken, err := b.Serialize()
if err != nil {
    panic(fmt.Errorf("failed to serialize biscuit: %v", err))
}

// token is now a []byte attenuation of the original token, and ready to be shared
```

#### Verify a biscuit

```go
b, err := biscuit.Unmarshal(token)
if err != nil {
    panic(fmt.Errorf("failed to deserialize token: %v", err))
}

rootPubKey := sig.NewPublicKey([]byte{/* root public key used in create step*/})

verifier, err := b.Verify(rootPubKey)
if err != nil {
    panic(fmt.Errorf("failed to create verifier: %v", err))
}

verifier.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
    Name: "resource", 
    IDs: []biscuit.Term{
        biscuit.SymbolAmbient, 
        biscuit.String("/a/file1.txt")
    }
}})

// ... add more ambient facts, rules, caveats...

verifier.AddPolicy(biscuit.DefaultAllowPolicy)

if err := verifier.Verify(); err != nil {
    fmt.Printf("failed to verify token: %v\n", err)
} else {
    fmt.Println("success verifying token")
}
```

### Using biscuit-go grammar

To ease adding facts, rules, or caveats, a simple grammar and a parser are available, allowing to declare biscuit elements as plain strings. See [GRAMMAR reference](./parser/GRAMMAR.md) for the complete syntax.

```go
p := parser.New()
b.AddFact(p.Must().Fact(`resource(#ambient, "/a/file1.txt")`))
b.AddRule(p.Must().Rule(`
    can_read($file) 
        <- resource(#ambient, $file) 
        @ prefix($file, "/a/")
`))
```

## Examples

- [example_test.go](./example_test.go) for a simple use case
- [experiments folder](./experiments) for more advanced or specific use cases examples.

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
