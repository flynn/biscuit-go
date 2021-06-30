package biscuit

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/biscuit-auth/biscuit-go/datalog"
)

const (
	SymbolAuthority = Symbol("authority")
	SymbolAmbient   = Symbol("ambient")
)

const MaxSchemaVersion uint32 = 1

// defaultSymbolTable predefines some symbols available in every implementation, to avoid
// transmitting them with every token
var defaultSymbolTable = &datalog.SymbolTable{
	string(SymbolAuthority),
	string(SymbolAmbient),
	"resource",
	"operation",
	"right",
	"current_time",
	"revocation_id",
}

type Block struct {
	index   uint32
	symbols *datalog.SymbolTable
	facts   *datalog.FactSet
	rules   []datalog.Rule
	checks  []datalog.Check
	context string
	version uint32
}

func (b *Block) String(symbols *datalog.SymbolTable) string {
	debug := &datalog.SymbolDebugger{
		SymbolTable: symbols,
	}
	rules := make([]string, len(b.rules))
	for i, r := range b.rules {
		rules[i] = debug.Rule(r)
	}

	checks := make([]string, len(b.checks))
	for i, c := range b.checks {
		checks[i] = debug.Check(c)
	}

	return fmt.Sprintf(`Block[%d] {
		symbols: %+q
		context: %q
		facts: %v
		rules: %v
		checks: %v
		version: %d
	}`,
		b.index,
		*b.symbols,
		b.context,
		debug.FactSet(b.facts),
		rules,
		checks,
		b.version,
	)
}

type FactSet []Fact

func (fs FactSet) String() string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.String())
	}

	var outStr string
	if len(out) > 0 {
		outStr = fmt.Sprintf("\n\t%s\n", strings.Join(out, ",\n\t"))
	}

	return fmt.Sprintf("[%s]", outStr)
}

type Fact struct {
	Predicate
}

func (f Fact) convert(symbols *datalog.SymbolTable) datalog.Fact {
	return datalog.Fact{
		Predicate: f.Predicate.convert(symbols),
	}
}
func (f Fact) String() string {
	return f.Predicate.String()
}

func fromDatalogFact(symbols *datalog.SymbolTable, f datalog.Fact) (*Fact, error) {
	pred, err := fromDatalogPredicate(symbols, f.Predicate)
	if err != nil {
		return nil, err
	}

	return &Fact{
		Predicate: *pred,
	}, nil
}

func fromDatalogPredicate(symbols *datalog.SymbolTable, p datalog.Predicate) (*Predicate, error) {
	terms := make([]Term, 0, len(p.IDs))
	for _, id := range p.IDs {
		a, err := fromDatalogID(symbols, id)
		if err != nil {
			return nil, err
		}
		terms = append(terms, a)
	}

	return &Predicate{
		Name: symbols.Str(p.Name),
		IDs:  terms,
	}, nil
}

func fromDatalogID(symbols *datalog.SymbolTable, id datalog.ID) (Term, error) {
	var a Term
	switch id.Type() {
	case datalog.IDTypeSymbol:
		a = Symbol(symbols.Str(id.(datalog.Symbol)))
	case datalog.IDTypeVariable:
		a = Variable(symbols.Str(datalog.Symbol(id.(datalog.Variable))))
	case datalog.IDTypeInteger:
		a = Integer(id.(datalog.Integer))
	case datalog.IDTypeString:
		a = String(id.(datalog.String))
	case datalog.IDTypeDate:
		a = Date(time.Unix(int64(id.(datalog.Date)), 0))
	case datalog.IDTypeBytes:
		a = Bytes(id.(datalog.Bytes))
	case datalog.IDTypeBool:
		a = Bool(id.(datalog.Bool))
	case datalog.IDTypeSet:
		setIDs := id.(datalog.Set)
		set := make(Set, 0, len(setIDs))
		for _, i := range setIDs {
			setTerm, err := fromDatalogID(symbols, i)
			if err != nil {
				return nil, err
			}
			set = append(set, setTerm)
		}
		a = set
	default:
		return nil, fmt.Errorf("unsupported term type: %v", id.Type())
	}

	return a, nil
}

type Rule struct {
	Head        Predicate
	Body        []Predicate
	Expressions []Expression
}

func (r Rule) convert(symbols *datalog.SymbolTable) datalog.Rule {
	dlBody := make([]datalog.Predicate, len(r.Body))
	for i, p := range r.Body {
		dlBody[i] = p.convert(symbols)
	}

	dlExpressions := make([]datalog.Expression, len(r.Expressions))
	for i, e := range r.Expressions {
		dlExpressions[i] = e.convert(symbols)
	}
	return datalog.Rule{
		Head:        r.Head.convert(symbols),
		Body:        dlBody,
		Expressions: dlExpressions,
	}
}

func fromDatalogRule(symbols *datalog.SymbolTable, dlRule datalog.Rule) (*Rule, error) {
	head, err := fromDatalogPredicate(symbols, dlRule.Head)
	if err != nil {
		return nil, fmt.Errorf("failed to convert datalog rule head: %v", err)
	}

	body := make([]Predicate, len(dlRule.Body))
	for i, dlPred := range dlRule.Body {
		pred, err := fromDatalogPredicate(symbols, dlPred)
		if err != nil {
			return nil, fmt.Errorf("failed to convert datalog rule body: %v", err)
		}
		body[i] = *pred
	}

	expressions := make([]Expression, len(dlRule.Expressions))
	for i, dlExpr := range dlRule.Expressions {
		expr, err := fromDatalogExpression(symbols, dlExpr)
		if err != nil {
			return nil, fmt.Errorf("failed to convert datalog rule expression: %v", err)
		}
		expressions[i] = expr
	}

	return &Rule{
		Head:        *head,
		Body:        body,
		Expressions: expressions,
	}, nil
}

type Expression []Op

func (e Expression) convert(symbols *datalog.SymbolTable) datalog.Expression {
	expr := make(datalog.Expression, len(e))
	for i, elt := range e {
		expr[i] = elt.convert(symbols)
	}
	return expr
}

func fromDatalogExpression(symbols *datalog.SymbolTable, dlExpr datalog.Expression) (Expression, error) {
	expr := make(Expression, len(dlExpr))
	for i, dlOP := range dlExpr {
		switch dlOP.Type() {
		case datalog.OpTypeValue:
			v, err := fromDatalogValueOp(symbols, dlOP.(datalog.Value))
			if err != nil {
				return nil, fmt.Errorf("failed to convert datalog expression value: %w", err)
			}
			expr[i] = v
		case datalog.OpTypeUnary:
			u, err := fromDatalogUnaryOp(symbols, dlOP.(datalog.UnaryOp))
			if err != nil {
				return nil, fmt.Errorf("failed to convert datalog unary expression: %w", err)
			}
			expr[i] = u
		case datalog.OpTypeBinary:
			b, err := fromDatalogBinaryOp(symbols, dlOP.(datalog.BinaryOp))
			if err != nil {
				return nil, fmt.Errorf("failed to convert datalog binary expression: %w", err)
			}
			expr[i] = b
		default:
			return nil, fmt.Errorf("unsupported datalog expression type: %v", dlOP.Type())
		}
	}
	return expr, nil
}

type Op interface {
	Type() OpType
	convert(symbols *datalog.SymbolTable) datalog.Op
}

type OpType byte

const (
	OpTypeValue OpType = iota
	OpTypeUnary
	OpTypeBinary
)

type Value struct {
	Term Term
}

func (v Value) Type() OpType {
	return OpTypeValue
}
func (v Value) convert(symbols *datalog.SymbolTable) datalog.Op {
	return datalog.Value{ID: v.Term.convert(symbols)}
}
func fromDatalogValueOp(symbols *datalog.SymbolTable, dlValue datalog.Value) (Op, error) {
	term, err := fromDatalogID(symbols, dlValue.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to convert datalog expression value: %v", err)
	}
	return Value{Term: term}, nil
}

type unaryOpType byte

type UnaryOp unaryOpType

const (
	UnaryUndefined UnaryOp = iota
	UnaryNegate
	UnaryParens
)

func (UnaryOp) Type() OpType {
	return OpTypeUnary
}
func (op UnaryOp) convert(symbols *datalog.SymbolTable) datalog.Op {
	switch op {
	case UnaryNegate:
		return datalog.UnaryOp{UnaryOpFunc: datalog.Negate{}}
	case UnaryParens:
		return datalog.UnaryOp{UnaryOpFunc: datalog.Parens{}}
	default:
		panic(fmt.Sprintf("biscuit: cannot convert invalid unary op type: %v", op))
	}
}

func fromDatalogUnaryOp(symbols *datalog.SymbolTable, dlUnary datalog.UnaryOp) (Op, error) {
	switch dlUnary.UnaryOpFunc.Type() {
	case datalog.UnaryNegate:
		return UnaryNegate, nil
	case datalog.UnaryParens:
		return UnaryParens, nil
	default:
		return UnaryUndefined, fmt.Errorf("unsupported datalog unary op: %v", dlUnary.UnaryOpFunc.Type())
	}
}

type binaryOpType byte

type BinaryOp binaryOpType

const (
	BinaryUndefined BinaryOp = iota
	BinaryLessThan
	BinaryLessOrEqual
	BinaryGreaterThan
	BinaryGreaterOrEqual
	BinaryEqual
	BinaryContains
	BinaryPrefix
	BinarySuffix
	BinaryRegex
	BinaryAdd
	BinarySub
	BinaryMul
	BinaryDiv
	BinaryAnd
	BinaryOr
)

func (BinaryOp) Type() OpType {
	return OpTypeBinary
}
func (op BinaryOp) convert(symbols *datalog.SymbolTable) datalog.Op {
	switch op {
	case BinaryLessThan:
		return datalog.BinaryOp{BinaryOpFunc: datalog.LessThan{}}
	case BinaryLessOrEqual:
		return datalog.BinaryOp{BinaryOpFunc: datalog.LessOrEqual{}}
	case BinaryGreaterThan:
		return datalog.BinaryOp{BinaryOpFunc: datalog.GreaterThan{}}
	case BinaryGreaterOrEqual:
		return datalog.BinaryOp{BinaryOpFunc: datalog.GreaterOrEqual{}}
	case BinaryEqual:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Equal{}}
	case BinaryContains:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}}
	case BinaryPrefix:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Prefix{}}
	case BinarySuffix:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Suffix{}}
	case BinaryRegex:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Regex{}}
	case BinaryAdd:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Add{}}
	case BinarySub:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Sub{}}
	case BinaryMul:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Mul{}}
	case BinaryDiv:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Div{}}
	case BinaryAnd:
		return datalog.BinaryOp{BinaryOpFunc: datalog.And{}}
	case BinaryOr:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Or{}}
	default:
		panic(fmt.Sprintf("biscuit: cannot convert invalid binary op type: %v", op))
	}
}

func fromDatalogBinaryOp(symbols *datalog.SymbolTable, dbBinary datalog.BinaryOp) (Op, error) {
	switch dbBinary.BinaryOpFunc.Type() {
	case datalog.BinaryLessThan:
		return BinaryLessThan, nil
	case datalog.BinaryLessOrEqual:
		return BinaryLessOrEqual, nil
	case datalog.BinaryGreaterThan:
		return BinaryGreaterThan, nil
	case datalog.BinaryGreaterOrEqual:
		return BinaryGreaterOrEqual, nil
	case datalog.BinaryEqual:
		return BinaryEqual, nil
	case datalog.BinaryContains:
		return BinaryContains, nil
	case datalog.BinaryPrefix:
		return BinaryPrefix, nil
	case datalog.BinarySuffix:
		return BinarySuffix, nil
	case datalog.BinaryRegex:
		return BinaryRegex, nil
	case datalog.BinaryAdd:
		return BinaryAdd, nil
	case datalog.BinarySub:
		return BinarySub, nil
	case datalog.BinaryMul:
		return BinaryMul, nil
	case datalog.BinaryDiv:
		return BinaryDiv, nil
	case datalog.BinaryAnd:
		return BinaryAnd, nil
	case datalog.BinaryOr:
		return BinaryOr, nil
	default:
		return BinaryUndefined, fmt.Errorf("unsupported datalog binary op: %v", dbBinary.BinaryOpFunc.Type())
	}
}

type Check struct {
	Queries []Rule
}

func (c Check) convert(symbols *datalog.SymbolTable) datalog.Check {
	queries := make([]datalog.Rule, len(c.Queries))
	for i, q := range c.Queries {
		queries[i] = q.convert(symbols)
	}

	return datalog.Check{
		Queries: queries,
	}
}

func fromDatalogCheck(symbols *datalog.SymbolTable, dlCheck datalog.Check) (*Check, error) {
	queries := make([]Rule, len(dlCheck.Queries))
	for i, q := range dlCheck.Queries {
		query, err := fromDatalogRule(symbols, q)
		if err != nil {
			return nil, fmt.Errorf("failed to convert datalog check query: %w", err)
		}
		queries[i] = *query
	}

	return &Check{
		Queries: queries,
	}, nil
}

type Predicate struct {
	Name string
	IDs  []Term
}

func (p Predicate) convert(symbols *datalog.SymbolTable) datalog.Predicate {
	var ids []datalog.ID
	for _, a := range p.IDs {
		ids = append(ids, a.convert(symbols))
	}

	return datalog.Predicate{
		Name: symbols.Insert(p.Name),
		IDs:  ids,
	}
}
func (p Predicate) String() string {
	terms := make([]string, 0, len(p.IDs))
	for _, a := range p.IDs {
		terms = append(terms, a.String())
	}
	return fmt.Sprintf("%s(%s)", p.Name, strings.Join(terms, ", "))
}

type TermType byte

const (
	TermTypeSymbol TermType = iota
	TermTypeVariable
	TermTypeInteger
	TermTypeString
	TermTypeDate
	TermTypeBytes
	TermTypeBool
	TermTypeSet
)

type Term interface {
	Type() TermType
	String() string
	convert(symbols *datalog.SymbolTable) datalog.ID
}

type Symbol string

func (a Symbol) Type() TermType { return TermTypeSymbol }
func (a Symbol) convert(symbols *datalog.SymbolTable) datalog.ID {
	return datalog.Symbol(symbols.Insert(string(a)))
}
func (a Symbol) String() string { return fmt.Sprintf("#%s", string(a)) }

type Variable string

func (a Variable) Type() TermType { return TermTypeVariable }
func (a Variable) convert(symbols *datalog.SymbolTable) datalog.ID {
	return datalog.Variable(symbols.Insert(string(a)))
}
func (a Variable) String() string { return fmt.Sprintf("$%s", string(a)) }

type Integer int64

func (a Integer) Type() TermType { return TermTypeInteger }
func (a Integer) convert(symbols *datalog.SymbolTable) datalog.ID {
	return datalog.Integer(a)
}
func (a Integer) String() string { return fmt.Sprintf("%d", a) }

type String string

func (a String) Type() TermType { return TermTypeString }
func (a String) convert(symbols *datalog.SymbolTable) datalog.ID {
	return datalog.String(a)
}
func (a String) String() string { return fmt.Sprintf("%q", string(a)) }

type Date time.Time

func (a Date) Type() TermType { return TermTypeDate }
func (a Date) convert(symbols *datalog.SymbolTable) datalog.ID {
	return datalog.Date(time.Time(a).Unix())
}
func (a Date) String() string { return time.Time(a).Format(time.RFC3339) }

type Bytes []byte

func (a Bytes) Type() TermType { return TermTypeBytes }
func (a Bytes) convert(symbols *datalog.SymbolTable) datalog.ID {
	return datalog.Bytes(a)
}
func (a Bytes) String() string { return fmt.Sprintf("hex:%s", hex.EncodeToString(a)) }

type Bool bool

func (b Bool) Type() TermType { return TermTypeBool }
func (b Bool) convert(symbols *datalog.SymbolTable) datalog.ID {
	return datalog.Bool(b)
}
func (b Bool) String() string { return fmt.Sprintf("%t", b) }

type Set []Term

func (a Set) Type() TermType { return TermTypeSet }
func (a Set) convert(symbols *datalog.SymbolTable) datalog.ID {
	datalogSet := make(datalog.Set, 0, len(a))
	for _, e := range a {
		datalogSet = append(datalogSet, e.convert(symbols))
	}
	return datalogSet
}
func (a Set) String() string {
	elts := make([]string, 0, len(a))
	for _, e := range a {
		elts = append(elts, e.String())
	}
	sort.Strings(elts)
	return fmt.Sprintf("[%s]", strings.Join(elts, ", "))
}

type PolicyKind byte

const (
	PolicyKindAllow = iota
	PolicyKindDeny
)

var (
	// DefaultAllowPolicy allows the biscuit to verify sucessfully as long as all its rules generate some facts.
	DefaultAllowPolicy = Policy{Kind: PolicyKindAllow, Queries: []Rule{{Head: Predicate{Name: "true"}}}}
	// DefaultDenyPolicy makes the biscuit verification fail in all cases.
	DefaultDenyPolicy = Policy{Kind: PolicyKindDeny, Queries: []Rule{{Head: Predicate{Name: "true"}}}}
)

type Policy struct {
	Queries []Rule
	Kind    PolicyKind
}
