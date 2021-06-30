package datalog

import (
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

// maxStackSize defines the maximum number of elements that can be stored on the stack.
// Trying to store more than maxStackSize elements returns an error.
const maxStackSize = 1000

var (
	ErrExprDivByZero = errors.New("datalog: Div by zero")
	ErrInt64Overflow = errors.New("datalog: expression overflowed int64")
)

type Expression []Op

func (e *Expression) Evaluate(values map[Variable]*ID) (ID, error) {
	s := &stack{}

	for _, op := range *e {
		switch op.Type() {
		case OpTypeValue:
			id := op.(Value).ID
			switch id.Type() {
			case IDTypeVariable:
				idptr, ok := values[id.(Variable)]
				if !ok {
					return nil, fmt.Errorf("datalog: expressions: unknown variable %d", id.(Variable))
				}
				id = *idptr
			}
			s.Push(id)
		case OpTypeUnary:
			v, err := s.Pop()
			if err != nil {
				return nil, fmt.Errorf("datalog: expressions: failed to pop unary value: %w", err)
			}

			res, err := op.(UnaryOp).Eval(v)
			if err != nil {
				return nil, fmt.Errorf("datalog: expressions: unary eval failed: %w", err)
			}
			s.Push(res)
		case OpTypeBinary:
			right, err := s.Pop()
			if err != nil {
				return nil, fmt.Errorf("datalog: expressions: failed to pop binary right value: %w", err)
			}
			left, err := s.Pop()
			if err != nil {
				return nil, fmt.Errorf("datalog: expressions: failed to pop binary left value: %w", err)
			}

			res, err := op.(BinaryOp).Eval(left, right)
			if err != nil {
				return nil, fmt.Errorf("datalog: expressions: binary eval failed: %w", err)
			}
			s.Push(res)
		default:
			return nil, fmt.Errorf("datalog: expressions: unsupported Op: %v", op.Type())
		}
	}

	// after processing all operations, there must be a single value left in the stack
	if len(*s) != 1 {
		return nil, fmt.Errorf("datalog: expressions: invalid resulting stack: %#v", *s)
	}

	return s.Pop()
}

func (e *Expression) Print(symbols *SymbolTable) string {
	s := &stack{}
	for _, op := range *e {
		switch op.Type() {
		case OpTypeValue:
			id := op.(Value).ID
			switch id.Type() {
			case IDTypeSymbol:
				s.Push(String(symbols.Str(id.(Symbol))))
			default:
				s.Push(String(id.String()))
			}
		case OpTypeUnary:
			v, err := s.Pop()
			if err != nil {
				return "<invalid expression: unary operation failed to pop value>"
			}
			res := op.(UnaryOp).Print(v.(String))
			if err != nil {
				return "<invalid expression: binary operation failed to pop right value>"
			}
			s.Push(String(res))
		case OpTypeBinary:
			right, err := s.Pop()
			if err != nil {
				return "<invalid expression: binary operation failed to pop right value>"
			}
			left, err := s.Pop()
			if err != nil {
				return "<invalid expression: binary operation failed to pop left value>"
			}
			res := op.(BinaryOp).Print(left.(String), right.(String))
			s.Push(String(res))
		default:
			return fmt.Sprintf("<invalid expression: unsupported op type %v>", op.Type())
		}
	}

	if len(*s) == 1 {
		v, err := s.Pop()
		if err != nil {
			return "<invalid expression: failed to pop result value>"
		}
		return string(v.(String))
	}

	return "<invalid expression: invalid resulting stack>"
}

type OpType byte

const (
	OpTypeValue OpType = iota
	OpTypeUnary
	OpTypeBinary
)

type Op interface {
	Type() OpType
}

type Value struct {
	ID ID
}

func (v Value) Type() OpType {
	return OpTypeValue
}

type UnaryOp struct {
	UnaryOpFunc
}

func (UnaryOp) Type() OpType {
	return OpTypeUnary
}
func (op UnaryOp) Print(value String) string {
	var out string
	switch op.UnaryOpFunc.Type() {
	case UnaryNegate:
		out = fmt.Sprintf("!%s", string(value))
	case UnaryParens:
		out = fmt.Sprintf("(%s)", string(value))
	default:
		out = fmt.Sprintf("unknown(%s)", string(value))
	}
	return out
}

type UnaryOpFunc interface {
	Type() UnaryOpType
	Eval(value ID) (ID, error)
}

type UnaryOpType byte

const (
	UnaryNegate UnaryOpType = iota
	UnaryParens
)

// Negate returns the negation of a value.
// It only accepts a Bool value.
type Negate struct{}

func (Negate) Type() UnaryOpType {
	return UnaryNegate
}
func (Negate) Eval(value ID) (ID, error) {
	var out ID
	switch value.Type() {
	case IDTypeBool:
		out = !value.(Bool)
	default:
		return nil, fmt.Errorf("datalog: unexpected Negate value type: %d", value.Type())
	}

	return out, nil
}

// Parens allows expression priority and grouping (like parenthesis in math operations)
// it is a no-op, but is used to print back the expressions properly, putting their value
// inside parenthesis.
type Parens struct{}

func (Parens) Type() UnaryOpType {
	return UnaryParens
}
func (Parens) Eval(value ID) (ID, error) {
	return value, nil
}

type BinaryOp struct {
	BinaryOpFunc
}

func (BinaryOp) Type() OpType {
	return OpTypeBinary
}
func (op BinaryOp) Print(left, right String) string {
	var out string
	switch op.BinaryOpFunc.Type() {
	case BinaryLessThan:
		out = fmt.Sprintf("%s < %s", string(left), string(right))
	case BinaryLessOrEqual:
		out = fmt.Sprintf("%s <= %s", string(left), string(right))
	case BinaryGreaterThan:
		out = fmt.Sprintf("%s > %s", string(left), string(right))
	case BinaryGreaterOrEqual:
		out = fmt.Sprintf("%s >= %s", string(left), string(right))
	case BinaryEqual:
		out = fmt.Sprintf("%s == %s", string(left), string(right))
	case BinaryContains:
		out = fmt.Sprintf("%s.contains(%s)", string(left), string(right))
	case BinaryPrefix:
		out = fmt.Sprintf("%s.starts_with(%s)", string(left), string(right))
	case BinarySuffix:
		out = fmt.Sprintf("%s.ends_with(%s)", string(left), string(right))
	case BinaryRegex:
		out = fmt.Sprintf("%s.matches(%s)", string(left), string(right))
	case BinaryAdd:
		out = fmt.Sprintf("%s + %s", string(left), string(right))
	case BinarySub:
		out = fmt.Sprintf("%s - %s", string(left), string(right))
	case BinaryMul:
		out = fmt.Sprintf("%s * %s", string(left), string(right))
	case BinaryDiv:
		out = fmt.Sprintf("%s / %s", string(left), string(right))
	case BinaryAnd:
		out = fmt.Sprintf("%s && %s", string(left), string(right))
	case BinaryOr:
		out = fmt.Sprintf("%s || %s", string(left), string(right))
	default:
		out = fmt.Sprintf("unknown(%s, %s)", string(left), string(right))
	}
	return out
}

type BinaryOpFunc interface {
	Type() BinaryOpType
	Eval(left, right ID) (ID, error)
}

type BinaryOpType byte

const (
	BinaryLessThan BinaryOpType = iota
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

// LessThan returns true when left is less than right.
// It requires left and right to have the same concrete type
// and only accepts Integer.
type LessThan struct{}

func (LessThan) Type() BinaryOpType {
	return BinaryLessThan
}
func (LessThan) Eval(left ID, right ID) (ID, error) {
	if g, w := left.Type(), right.Type(); g != w {
		return nil, fmt.Errorf("datalog: LessThan type mismatch: %d != %d", g, w)
	}

	var out ID
	switch left.Type() {
	case IDTypeInteger:
		out = Bool(left.(Integer) < right.(Integer))
	default:
		return nil, fmt.Errorf("datalog: unexpected LessThan value type: %d", left.Type())
	}

	return out, nil
}

// LessOrEqual returns true when left is less or equal than right.
// It requires left and right to have the same concrete type
// and only accepts Integer and Date.
type LessOrEqual struct{}

func (LessOrEqual) Type() BinaryOpType {
	return BinaryLessOrEqual
}
func (LessOrEqual) Eval(left ID, right ID) (ID, error) {
	if g, w := left.Type(), right.Type(); g != w {
		return nil, fmt.Errorf("datalog: LessOrEqual type mismatch: %d != %d", g, w)
	}

	var out ID
	switch left.Type() {
	case IDTypeInteger:
		out = Bool(left.(Integer) <= right.(Integer))
	case IDTypeDate:
		out = Bool(left.(Date) <= right.(Date))
	default:
		return nil, fmt.Errorf("datalog: unexpected LessOrEqual value type: %d", left.Type())
	}

	return out, nil
}

// GreaterThan returns true when left is greater than right.
// It requires left and right to have the same concrete type
// and only accepts Integer.
type GreaterThan struct{}

func (GreaterThan) Type() BinaryOpType {
	return BinaryGreaterThan
}
func (GreaterThan) Eval(left ID, right ID) (ID, error) {
	if g, w := left.Type(), right.Type(); g != w {
		return nil, fmt.Errorf("datalog: GreaterThan type mismatch: %d != %d", g, w)
	}

	var out ID
	switch left.Type() {
	case IDTypeInteger:
		out = Bool(left.(Integer) > right.(Integer))
	default:
		return nil, fmt.Errorf("datalog: unexpected GreaterThan value type: %d", left.Type())
	}

	return out, nil
}

// GreaterOrEqual returns true when left is greater than right.
// It requires left and right to have the same concrete type
// and only accepts Integer and Date.
type GreaterOrEqual struct{}

func (GreaterOrEqual) Type() BinaryOpType {
	return BinaryGreaterOrEqual
}
func (GreaterOrEqual) Eval(left ID, right ID) (ID, error) {
	if g, w := left.Type(), right.Type(); g != w {
		return nil, fmt.Errorf("datalog: GreaterOrEqual type mismatch: %d != %d", g, w)
	}

	var out ID
	switch left.Type() {
	case IDTypeInteger:
		out = Bool(left.(Integer) >= right.(Integer))
	case IDTypeDate:
		out = Bool(left.(Date) >= right.(Date))
	default:
		return nil, fmt.Errorf("datalog: unexpected GreaterOrEqual value type: %d", left.Type())
	}

	return out, nil
}

// Equal returns true when left and right are equal.
// It requires left and right to have the same concrete type
// and only accepts Integer, Bytes or String.
type Equal struct{}

func (Equal) Type() BinaryOpType {
	return BinaryEqual
}
func (Equal) Eval(left ID, right ID) (ID, error) {
	if g, w := left.Type(), right.Type(); g != w {
		return nil, fmt.Errorf("datalog: Equal type mismatch: %d != %d", g, w)
	}

	switch left.Type() {
	case IDTypeInteger:
	case IDTypeBytes:
	case IDTypeString:
	default:
		return nil, fmt.Errorf("datalog: unexpected Equal value type: %d", left.Type())
	}

	return Bool(left.Equal(right)), nil
}

// Contains returns true when the right value exists in the left Set.
// The right value must be an Integer, Bytes, String or Symbol.
// The left value must be a Set, containing elements of right type.
type Contains struct{}

func (Contains) Type() BinaryOpType {
	return BinaryContains
}
func (Contains) Eval(left ID, right ID) (ID, error) {
	switch right.Type() {
	case IDTypeInteger:
	case IDTypeBytes:
	case IDTypeString:
	case IDTypeSymbol:
	default:
		return nil, fmt.Errorf("datalog: unexpected Contains right value type: %d", right.Type())
	}

	set, ok := left.(Set)
	if !ok {
		return nil, errors.New("datalog: Contains left value must be a Set")
	}

	for _, elt := range set {
		if g, w := elt.Type(), right.Type(); g != w {
			return nil, fmt.Errorf("datalog: unexpected Contains set element type: got %d, want %d", g, w)
		}
		if right.Equal(elt) {
			return Bool(true), nil
		}
	}

	return Bool(false), nil
}

// Prefix returns true when the left string starts with the right string.
// left and right must be String.
type Prefix struct{}

func (Prefix) Type() BinaryOpType {
	return BinaryPrefix
}
func (Prefix) Eval(left ID, right ID) (ID, error) {
	sleft, ok := left.(String)
	if !ok {
		return nil, fmt.Errorf("datalog: Prefix requires left value to be a String, got %T", left)
	}
	sright, ok := right.(String)
	if !ok {
		return nil, fmt.Errorf("datalog: Prefix requires right value to be a String, got %T", right)
	}

	return Bool(strings.HasPrefix(string(sleft), string(sright))), nil
}

// Suffix returns true when the left string ends with the right string.
// left and right must be String.
type Suffix struct{}

func (Suffix) Type() BinaryOpType {
	return BinarySuffix
}
func (Suffix) Eval(left ID, right ID) (ID, error) {
	sleft, ok := left.(String)
	if !ok {
		return nil, fmt.Errorf("datalog: Suffix requires left value to be a String, got %T", left)
	}
	sright, ok := right.(String)
	if !ok {
		return nil, fmt.Errorf("datalog: Suffix requires right value to be a String, got %T", right)
	}

	return Bool(strings.HasSuffix(string(sleft), string(sright))), nil
}

// Regex returns true when the right string is a regexp and left matches against it.
// left and right must be String.
type Regex struct{}

func (Regex) Type() BinaryOpType {
	return BinaryRegex
}
func (Regex) Eval(left ID, right ID) (ID, error) {
	sleft, ok := left.(String)
	if !ok {
		return nil, fmt.Errorf("datalog: Regex requires left value to be a String, got %T", left)
	}
	sright, ok := right.(String)
	if !ok {
		return nil, fmt.Errorf("datalog: Regex requires right value to be a String, got %T", right)
	}

	re, err := regexp.Compile(string(sright))
	if err != nil {
		return nil, fmt.Errorf("datalog: invalid regex: %q: %v", right, err)
	}
	return Bool(re.Match([]byte(sleft))), nil
}

// Add performs the addition of left + right and returns the result.
// It requires left and right to be Integer.
type Add struct{}

func (Add) Type() BinaryOpType {
	return BinaryAdd
}
func (Add) Eval(left ID, right ID) (ID, error) {
	ileft, ok := left.(Integer)
	if !ok {
		return nil, fmt.Errorf("datalog: Add requires left value to be an Integer, got %T", left)
	}
	iright, ok := right.(Integer)
	if !ok {
		return nil, fmt.Errorf("datalog: Add requires right value to be an Integer, got %T", right)
	}

	bleft := big.NewInt(int64(ileft))
	bright := big.NewInt(int64(iright))
	res := big.NewInt(0)
	res.Add(bleft, bright)

	if !res.IsInt64() {
		return nil, ErrInt64Overflow
	}
	return Integer(res.Int64()), nil
}

// Sub performs the substraction of left - right and returns the result.
// It requires left and right to be Integer.
type Sub struct{}

func (Sub) Type() BinaryOpType {
	return BinarySub
}
func (Sub) Eval(left ID, right ID) (ID, error) {
	ileft, ok := left.(Integer)
	if !ok {
		return nil, fmt.Errorf("datalog: Sub requires left value to be an Integer, got %T", left)
	}
	iright, ok := right.(Integer)
	if !ok {
		return nil, fmt.Errorf("datalog: Sub requires right value to be an Integer, got %T", right)
	}

	bleft := big.NewInt(int64(ileft))
	bright := big.NewInt(int64(iright))
	res := big.NewInt(0)
	res.Sub(bleft, bright)

	if !res.IsInt64() {
		return nil, ErrInt64Overflow
	}
	return Integer(res.Int64()), nil
}

// Mul performs the multiplication of left * right and returns the result.
// It requires left and right to be Integer.
type Mul struct{}

func (Mul) Type() BinaryOpType {
	return BinaryMul
}
func (Mul) Eval(left ID, right ID) (ID, error) {
	ileft, ok := left.(Integer)
	if !ok {
		return nil, fmt.Errorf("datalog: Mul requires left value to be an Integer, got %T", left)
	}
	iright, ok := right.(Integer)
	if !ok {
		return nil, fmt.Errorf("datalog: Mul requires right value to be an Integer, got %T", right)
	}

	bleft := big.NewInt(int64(ileft))
	bright := big.NewInt(int64(iright))
	res := big.NewInt(0)
	res.Mul(bleft, bright)

	if !res.IsInt64() {
		return nil, ErrInt64Overflow
	}

	return Integer(res.Int64()), nil
}

// Div performs the division of left / right and returns the result.
// It requires left and right to be Integer.
type Div struct{}

func (Div) Type() BinaryOpType {
	return BinaryDiv
}
func (Div) Eval(left ID, right ID) (ID, error) {
	ileft, ok := left.(Integer)
	if !ok {
		return nil, fmt.Errorf("datalog: Div requires left value to be an Integer, got %T", left)
	}
	iright, ok := right.(Integer)
	if !ok {
		return nil, fmt.Errorf("datalog: Div requires right value to be an Integer, got %T", right)
	}

	if iright == 0 {
		return nil, ErrExprDivByZero
	}

	return Integer(ileft / iright), nil
}

// And performs a logical AND between left and right and returns a Bool.
// It requires left and right to be Bool.
type And struct{}

func (And) Type() BinaryOpType {
	return BinaryAnd
}
func (And) Eval(left ID, right ID) (ID, error) {
	bleft, ok := left.(Bool)
	if !ok {
		return nil, fmt.Errorf("datalog: And requires left value to be a Bool, got %T", left)
	}
	bright, ok := right.(Bool)
	if !ok {
		return nil, fmt.Errorf("datalog: And requires right value to be a Bool, got %T", right)
	}

	return Bool(bleft && bright), nil
}

// Or performs a logical OR between left and right and returns a Bool.
// It requires left and right to be Bool.
type Or struct{}

func (Or) Type() BinaryOpType {
	return BinaryOr
}
func (Or) Eval(left ID, right ID) (ID, error) {
	bleft, ok := left.(Bool)
	if !ok {
		return nil, fmt.Errorf("datalog: Or requires left value to be a Bool, got %T", left)
	}
	bright, ok := right.(Bool)
	if !ok {
		return nil, fmt.Errorf("datalog: Or requires right value to be a Bool, got %T", right)
	}

	return Bool(bleft || bright), nil
}

type stack []ID

func (s *stack) Push(v ID) error {
	if len(*s) >= maxStackSize {
		return errors.New("stack overflow")
	}

	*s = append(*s, v)

	return nil
}

func (s *stack) Pop() (ID, error) {
	if len(*s) == 0 {
		return nil, errors.New("cannot pop from empty stack")
	}

	e := (*s)[len(*s)-1]
	*s = (*s)[:len(*s)-1]

	return e, nil
}
