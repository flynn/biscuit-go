package parser

import (
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer"
	"github.com/biscuit-auth/biscuit-go"
)

type Comment string

func (c *Comment) Capture(values []string) error {
	if len(values) != 1 {
		return errors.New("parser: invalid comment values")
	}
	if !strings.HasPrefix(values[0], "//") {
		return errors.New("parser: invalid comment prefix")
	}
	*c = Comment(strings.TrimSpace(strings.TrimPrefix(values[0], "//")))
	return nil
}

type Symbol string

func (s *Symbol) Capture(values []string) error {
	if len(values) != 1 {
		return errors.New("parser: invalid symbol values")
	}
	if !strings.HasPrefix(values[0], "#") {
		return errors.New("parser: invalid symbol prefix")
	}
	*s = Symbol(strings.TrimPrefix(values[0], "#"))
	return nil
}

type Variable string

func (v *Variable) Capture(values []string) error {
	if len(values) != 1 {
		return errors.New("parser: invalid variable values")
	}
	if !strings.HasPrefix(values[0], "$") {
		return errors.New("parser: invalid variable prefix")
	}
	*v = Variable(strings.TrimPrefix(values[0], "$"))
	return nil
}

type Bool bool

func (b *Bool) Capture(values []string) error {
	if len(values) != 1 {
		return errors.New("parser: invalid bool values")
	}
	v, err := strconv.ParseBool(values[0])
	if err != nil {
		return err
	}
	*b = Bool(v)
	return nil
}

type Rule struct {
	Comments    []*Comment    `@Comment*`
	Head        *Predicate    `@@`
	Body        []*Predicate  `"<-" @@ ("," @@)*`
	Constraints []*Constraint `("@" @@ ("," @@)*)*`
}

type Predicate struct {
	Name *string `@Ident`
	IDs  []*Term `"(" (@@ ("," @@)*)* ")"`
}

type Check struct {
	Queries []*Rule `"[" @@ ( "||" @@ )* "]"`
}

type Term struct {
	Symbol   *Symbol    `@Symbol`
	Variable *Variable  `| @Variable`
	Bytes    *HexString `| @@`
	String   *string    `| @String`
	Integer  *int64     `| @Int`
	Bool     *Bool      `| @Bool`
	Set      []*Term    `| "[" @@ ("," @@)* "]"`
}

type Constraint struct {
	VariableConstraint *VariableConstraint `@@`
	FunctionConstraint *FunctionConstraint `| @@`
}

type VariableConstraint struct {
	Variable *Variable         `@Variable`
	Date     *DateComparison   `((@@`
	Bytes    *BytesComparison  `| @@`
	String   *StringComparison `| @@`
	Int      *IntComparison    `| @@)`
	Set      *Set              `| @@)`
}

type FunctionConstraint struct {
	Function *string   `@Function "("`
	Variable *Variable `@Variable ","`
	Argument *string   `@String ")"`
}

type IntComparison struct {
	Operation *string `@("=="|">="|"<="|">"|"<")`
	Target    *int64  `@Int`
}

type StringComparison struct {
	Operation *string `@("==")`
	Target    *string `@String`
}

type BytesComparison struct {
	Operation *string    `@("==")`
	Target    *HexString `@@`
}

type DateComparison struct {
	Operation *string `@("<=" | ">=")`
	Target    *string `@String`
}

type Set struct {
	Not     bool        `@"not"? "in"`
	Symbols []Symbol    `("[" ( @Symbol ("," @Symbol)*)+ "]"`
	Bytes   []HexString `| "[" ( @@ ("," @@)*)+ "]"`
	String  []string    `| "[" (@String ("," @String)*)+ "]"`
	Int     []int64     `| "[" (@Int ("," @Int)*)+ "]")`
}

type HexString string

func (h *HexString) Parse(lex *lexer.PeekingLexer) error {
	token, err := lex.Peek(0)
	if err != nil {
		return err
	}

	if !strings.HasPrefix(token.Value, "hex:") {
		return participle.NextMatch
	}

	_, err = lex.Next()
	if err != nil {
		return err
	}

	*h = HexString(strings.TrimPrefix(token.Value, "hex:"))

	return nil
}

func (h *HexString) Decode() ([]byte, error) {
	return hex.DecodeString(string(*h))
}

func (h *HexString) String() string {
	return string(*h)
}

func (p *Predicate) ToBiscuit() (*biscuit.Predicate, error) {
	terms := make([]biscuit.Term, 0, len(p.IDs))
	for _, a := range p.IDs {
		biscuitTerm, err := a.ToBiscuit()
		if err != nil {
			return nil, err
		}
		terms = append(terms, biscuitTerm)
	}

	return &biscuit.Predicate{
		Name: *p.Name,
		IDs:  terms,
	}, nil
}

func (a *Term) ToBiscuit() (biscuit.Term, error) {
	var biscuitTerm biscuit.Term
	switch {
	case a.Integer != nil:
		biscuitTerm = biscuit.Integer(*a.Integer)
	case a.String != nil:
		biscuitTerm = biscuit.String(*a.String)
	case a.Symbol != nil:
		biscuitTerm = biscuit.Symbol(*a.Symbol)
	case a.Variable != nil:
		biscuitTerm = biscuit.Variable(*a.Variable)
	case a.Bytes != nil:
		b, err := a.Bytes.Decode()
		if err != nil {
			return nil, fmt.Errorf("parser: failed to decode hex string: %v", err)
		}
		biscuitTerm = biscuit.Bytes(b)
	case a.Bool != nil:
		biscuitTerm = biscuit.Bool(*a.Bool)
	case a.Set != nil:
		biscuitSet := make(biscuit.Set, 0, len(a.Set))
		for _, term := range a.Set {
			setTerm, err := term.ToBiscuit()
			if err != nil {
				return nil, err
			}
			if setTerm.Type() == biscuit.TermTypeVariable {
				return nil, ErrVariableInSet
			}
			biscuitSet = append(biscuitSet, setTerm)
		}
		biscuitTerm = biscuitSet
	default:
		return nil, errors.New("parser: unsupported predicate, must be one of integer, string, symbol, variable, or bytes")
	}

	return biscuitTerm, nil
}

func (c *Constraint) ToExpr() (biscuit.Expression, error) {
	var expr biscuit.Expression
	var err error

	switch {
	case c.VariableConstraint != nil:
		expr, err = c.VariableConstraint.ToExpr()
	case c.FunctionConstraint != nil:
		expr, err = c.FunctionConstraint.ToExpr()
	default:
		err = errors.New("parser: unsupported constraint, must be one of variable or function")
	}

	if err != nil {
		return nil, err
	}

	return expr, nil
}

func (c *VariableConstraint) ToExpr() (biscuit.Expression, error) {
	var expr biscuit.Expression
	switch {
	case c.Date != nil:
		date, err := time.Parse(time.RFC3339, *c.Date.Target)
		if err != nil {
			return nil, err
		}
		switch *c.Date.Operation {
		case "<=":
			expr = biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable(*c.Variable)},
				biscuit.Value{Term: biscuit.Date(date)},
				biscuit.BinaryLessOrEqual,
			}
		case ">=":
			expr = biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable(*c.Variable)},
				biscuit.Value{Term: biscuit.Date(date)},
				biscuit.BinaryGreaterOrEqual,
			}
		default:
			return nil, fmt.Errorf("parser: unsupported date operation: %s", *c.Date.Operation)
		}
	case c.Int != nil:
		switch *c.Int.Operation {
		case "<":
			expr = biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable(*c.Variable)},
				biscuit.Value{Term: biscuit.Integer(*c.Int.Target)},
				biscuit.BinaryLessThan,
			}
		case "<=":
			expr = biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable(*c.Variable)},
				biscuit.Value{Term: biscuit.Integer(*c.Int.Target)},
				biscuit.BinaryLessOrEqual,
			}
		case "==":
			expr = biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable(*c.Variable)},
				biscuit.Value{Term: biscuit.Integer(*c.Int.Target)},
				biscuit.BinaryEqual,
			}
		case ">":
			expr = biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable(*c.Variable)},
				biscuit.Value{Term: biscuit.Integer(*c.Int.Target)},
				biscuit.BinaryGreaterThan,
			}
		case ">=":
			expr = biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable(*c.Variable)},
				biscuit.Value{Term: biscuit.Integer(*c.Int.Target)},
				biscuit.BinaryGreaterOrEqual,
			}
		default:
			return nil, fmt.Errorf("parser: unsupported int operation: %s", *c.Int.Operation)
		}
	case c.String != nil:
		expr = biscuit.Expression{
			biscuit.Value{Term: biscuit.Variable(*c.Variable)},
			biscuit.Value{Term: biscuit.String(*c.String.Target)},
			biscuit.BinaryEqual,
		}
	case c.Bytes != nil:
		switch *c.Bytes.Operation {
		case "==":
			b, err := c.Bytes.Target.Decode()
			if err != nil {
				return nil, fmt.Errorf("parser: failed to decode hex string: %v", err)
			}
			expr = biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable(*c.Variable)},
				biscuit.Value{Term: biscuit.Bytes(b)},
				biscuit.BinaryEqual,
			}
		default:
			return nil, fmt.Errorf("parser: unsupported bytes operation: %s", *c.Bytes.Operation)
		}
	case c.Set != nil:
		var set []biscuit.Term
		switch {
		case c.Set.Symbols != nil:
			set := make([]biscuit.Term, len(c.Set.Symbols))
			for i, s := range c.Set.Symbols {
				set[i] = biscuit.Symbol(s)
			}
		case c.Set.Int != nil:
			set := make([]biscuit.Term, len(c.Set.Int))
			for i, s := range c.Set.Int {
				set[i] = biscuit.Integer(s)
			}
		case c.Set.String != nil:
			set := make([]biscuit.Term, len(c.Set.String))
			for i, s := range c.Set.String {
				set[i] = biscuit.String(s)
			}
		case c.Set.Bytes != nil:
			set := make([]biscuit.Term, len(c.Set.Bytes))
			for i, s := range c.Set.Bytes {
				b, err := s.Decode()
				if err != nil {
					return nil, fmt.Errorf("parser: failed to decode hex string: %v", err)
				}
				set[i] = biscuit.Bytes(b)
			}
		default:
			return nil, errors.New("parser: unsupported set type, must be one of symbols, int, string, or bytes")
		}

		expr = biscuit.Expression{
			biscuit.Value{Term: biscuit.Variable(*c.Variable)},
			biscuit.Value{Term: biscuit.Set(set)},
			biscuit.BinaryContains,
		}

		if c.Set.Not {
			expr = append(expr, biscuit.UnaryNegate)
		}

	default:
		return nil, errors.New("parser: unsupported variable constraint, must be one of date, int, string, bytes, or set")
	}
	return expr, nil
}

func (c *FunctionConstraint) ToExpr() (biscuit.Expression, error) {
	var expr biscuit.Expression
	switch *c.Function {
	case "prefix":
		expr = biscuit.Expression{
			biscuit.Value{Term: biscuit.Variable(*c.Variable)},
			biscuit.Value{Term: biscuit.String(*c.Argument)},
			biscuit.BinaryPrefix,
		}
	case "suffix":
		expr = biscuit.Expression{
			biscuit.Value{Term: biscuit.Variable(*c.Variable)},
			biscuit.Value{Term: biscuit.String(*c.Argument)},
			biscuit.BinarySuffix,
		}
	case "match":
		if _, err := regexp.Compile(*c.Argument); err != nil {
			return nil, err
		}
		expr = biscuit.Expression{
			biscuit.Value{Term: biscuit.Variable(*c.Variable)},
			biscuit.Value{Term: biscuit.String(*c.Argument)},
			biscuit.BinaryRegex,
		}
	default:
		return nil, fmt.Errorf("parser: unsupported function: %s", *c.Function)
	}

	return expr, nil
}

func (r *Rule) ToBiscuit() (*biscuit.Rule, error) {
	body := make([]biscuit.Predicate, len(r.Body))
	for i, p := range r.Body {
		b, err := p.ToBiscuit()
		if err != nil {
			return nil, err
		}
		body[i] = *b
	}

	expressions := make([]biscuit.Expression, len(r.Constraints))
	for i, c := range r.Constraints {
		expr, err := c.ToExpr()
		if err != nil {
			return nil, err
		}
		expressions[i] = expr
	}

	head, err := r.Head.ToBiscuit()
	if err != nil {
		return nil, err
	}

	return &biscuit.Rule{
		Head:        *head,
		Body:        body,
		Expressions: expressions,
	}, nil
}

func (c *Check) ToBiscuit() (*biscuit.Check, error) {
	queries := make([]biscuit.Rule, 0, len(c.Queries))
	for _, q := range c.Queries {
		r, err := q.ToBiscuit()
		if err != nil {
			return nil, err
		}

		queries = append(queries, *r)
	}

	return &biscuit.Check{
		Queries: queries,
	}, nil
}
