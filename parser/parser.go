package parser

import (
	"errors"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer/stateful"
	"github.com/biscuit-auth/biscuit-go"
)

var (
	ErrVariableInFact = errors.New("parser: a fact cannot contain any variables")
	ErrVariableInSet  = errors.New("parser: a set cannot contain any variables")
)

var BiscuitLexerRules = []stateful.Rule{
	{Name: "Keyword", Pattern: `rules|checks`, Action: nil},
	{Name: "Function", Pattern: `prefix|suffix|match`, Action: nil},
	{Name: "Arrow", Pattern: `<-`, Action: nil},
	{Name: "Or", Pattern: `\|\|`, Action: nil},
	{Name: "Operator", Pattern: `==|>=|<=|>|<|not|in`, Action: nil},
	{Name: "Comment", Pattern: `//[^\n]*`, Action: nil},
	{Name: "String", Pattern: `\"[^\"]*\"`, Action: nil},
	{Name: "Variable", Pattern: `\$[a-zA-Z0-9_]+`, Action: nil},
	{Name: "Int", Pattern: `[0-9]+`, Action: nil},
	{Name: "Bool", Pattern: `true|false`, Action: nil},
	{Name: "Symbol", Pattern: `#[a-zA-Z0-9_]+`, Action: nil},
	{Name: "Ident", Pattern: `[a-zA-Z0-9_]+`, Action: nil},
	{Name: "Whitespace", Pattern: `[ \t]+`, Action: nil},
	{Name: "EOL", Pattern: `[\n\r]+`, Action: nil},
	{Name: "Punct", Pattern: `[-[!@%^&#$*()+_={}\|:;"'<,>.?/]|]`, Action: nil},
}

var DefaultParserOptions = []participle.Option{
	participle.Lexer(stateful.MustSimple(BiscuitLexerRules)),
	participle.UseLookahead(1),
	participle.Elide("Whitespace", "EOL"),
	participle.Unquote("String"),
}

type Parser interface {
	Fact(fact string) (biscuit.Fact, error)
	Rule(rule string) (biscuit.Rule, error)
	Check(check string) (biscuit.Check, error)
	Must() MustParser
}

type MustParser interface {
	Fact(fact string) biscuit.Fact
	Rule(rule string) biscuit.Rule
	Check(check string) biscuit.Check
}

type parser struct {
	factParser  *participle.Parser
	ruleParser  *participle.Parser
	checkParser *participle.Parser
}

var _ Parser = (*parser)(nil)

type mustParser struct {
	parser Parser
}

var _ MustParser = (*mustParser)(nil)

func New() Parser {
	return &parser{
		factParser:  participle.MustBuild(&Predicate{}, DefaultParserOptions...),
		ruleParser:  participle.MustBuild(&Rule{}, DefaultParserOptions...),
		checkParser: participle.MustBuild(&Check{}, DefaultParserOptions...),
	}
}

func (p *parser) Fact(fact string) (biscuit.Fact, error) {
	parsed := &Predicate{}
	if err := p.factParser.ParseString("fact", fact, parsed); err != nil {
		return biscuit.Fact{}, err
	}

	pred, err := parsed.ToBiscuit()
	if err != nil {
		return biscuit.Fact{}, err
	}

	for _, a := range pred.IDs {
		if a.Type() == biscuit.TermTypeVariable {
			return biscuit.Fact{}, ErrVariableInFact
		}
	}

	return biscuit.Fact{Predicate: *pred}, nil
}

func (p *parser) Rule(rule string) (biscuit.Rule, error) {
	parsed := &Rule{}
	if err := p.ruleParser.ParseString("rule", rule, parsed); err != nil {
		return biscuit.Rule{}, err
	}

	r, err := parsed.ToBiscuit()
	if err != nil {
		return biscuit.Rule{}, err
	}

	return *r, nil
}

func (p *parser) Check(check string) (biscuit.Check, error) {
	parsed := &Check{}
	if err := p.checkParser.ParseString("check", check, parsed); err != nil {
		return biscuit.Check{}, err
	}

	queries := make([]biscuit.Rule, len(parsed.Queries))
	for i, q := range parsed.Queries {
		query, err := q.ToBiscuit()
		if err != nil {
			return biscuit.Check{}, err
		}

		queries[i] = *query
	}

	return biscuit.Check{
		Queries: queries,
	}, nil
}

func (p *parser) Must() MustParser {
	return &mustParser{parser: p}
}

func (m *mustParser) Fact(fact string) biscuit.Fact {
	f, err := m.parser.Fact(fact)
	if err != nil {
		panic(err)
	}

	return f
}

func (m *mustParser) Rule(rule string) biscuit.Rule {
	r, err := m.parser.Rule(rule)
	if err != nil {
		panic(err)
	}

	return r
}

func (m *mustParser) Check(check string) biscuit.Check {
	c, err := m.parser.Check(check)
	if err != nil {
		panic(err)
	}

	return c
}
