package datalog

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

type IDType byte

const (
	IDTypeSymbol IDType = iota
	IDTypeVariable
	IDTypeInteger
	IDTypeString
	IDTypeDate
	IDTypeBytes
	IDTypeBool
	IDTypeSet
)

type ID interface {
	Type() IDType
	Equal(ID) bool
	String() string
}

type Set []ID

func (Set) Type() IDType { return IDTypeSet }
func (s Set) Equal(t ID) bool {
	c, ok := t.(Set)
	if !ok || len(c) != len(s) {
		return false
	}

	cmap := make(map[ID]struct{}, len(c))
	for _, v := range c {
		cmap[v] = struct{}{}
	}

	for _, id := range s {
		if _, ok := cmap[id]; !ok {
			return false
		}
	}
	return true
}
func (s Set) String() string {
	eltStr := make([]string, 0, len(s))
	for _, e := range s {
		eltStr = append(eltStr, e.String())
	}
	sort.Strings(eltStr)
	return fmt.Sprintf("[%s]", strings.Join(eltStr, ", "))
}

type Symbol uint64

func (Symbol) Type() IDType      { return IDTypeSymbol }
func (s Symbol) Equal(t ID) bool { c, ok := t.(Symbol); return ok && s == c }
func (s Symbol) String() string {
	return fmt.Sprintf("#%d", s)
}

type Variable uint32

func (Variable) Type() IDType      { return IDTypeVariable }
func (v Variable) Equal(t ID) bool { c, ok := t.(Variable); return ok && v == c }
func (v Variable) String() string {
	return fmt.Sprintf("$%d", v)
}

type Integer int64

func (Integer) Type() IDType      { return IDTypeInteger }
func (i Integer) Equal(t ID) bool { c, ok := t.(Integer); return ok && i == c }
func (i Integer) String() string {
	return fmt.Sprintf("%d", i)
}

type String string

func (String) Type() IDType      { return IDTypeString }
func (s String) Equal(t ID) bool { c, ok := t.(String); return ok && s == c }
func (s String) String() string {
	return fmt.Sprintf("%q", string(s))
}

type Date uint64

func (Date) Type() IDType      { return IDTypeDate }
func (d Date) Equal(t ID) bool { c, ok := t.(Date); return ok && d == c }
func (d Date) String() string {
	return time.Unix(int64(d), 0).Format(time.RFC3339)
}

type Bytes []byte

func (Bytes) Type() IDType      { return IDTypeBytes }
func (b Bytes) Equal(t ID) bool { c, ok := t.(Bytes); return ok && bytes.Equal(b, c) }
func (b Bytes) String() string {
	return fmt.Sprintf("\"hex:%s\"", hex.EncodeToString(b))
}

type Bool bool

func (Bool) Type() IDType      { return IDTypeBool }
func (b Bool) Equal(t ID) bool { c, ok := t.(Bool); return ok && b == c }
func (b Bool) String() string {
	return fmt.Sprintf("%t", b)
}

type Predicate struct {
	Name Symbol
	IDs  []ID
}

func (p Predicate) Equal(p2 Predicate) bool {
	if p.Name != p2.Name || len(p.IDs) != len(p2.IDs) {
		return false
	}
	for i, id := range p.IDs {
		if !id.Equal(p2.IDs[i]) {
			return false
		}
	}

	return true
}

func (p Predicate) Match(p2 Predicate) bool {
	if p.Name != p2.Name || len(p.IDs) != len(p2.IDs) {
		return false
	}
	for i, id := range p.IDs {
		_, v1 := id.(Variable)
		_, v2 := p2.IDs[i].(Variable)
		if v1 || v2 {
			continue
		}
		if !id.Equal(p2.IDs[i]) {
			return false
		}
	}
	return true
}

func (p Predicate) Clone() Predicate {
	res := Predicate{Name: p.Name, IDs: make([]ID, len(p.IDs))}
	copy(res.IDs, p.IDs)
	return res
}

type Fact struct {
	Predicate
}

type Rule struct {
	Head        Predicate
	Body        []Predicate
	Expressions []Expression

	forbiddenIDs []ID
}

type InvalidRuleError struct {
	Rule            Rule
	MissingVariable Variable
}

func (e InvalidRuleError) Error() string {
	return fmt.Sprintf("datalog: variable %d in head is missing from body and/or constraints", e.MissingVariable)
}

func (r Rule) Apply(facts *FactSet, newFacts *FactSet) error {
	// extract all variables from the rule body
	variables := make(MatchedVariables)
	for _, p := range r.Body {
		for _, id := range p.IDs {
			v, ok := id.(Variable)
			if !ok {
				continue
			}
			variables[v] = nil
		}
	}

	combined, err := NewCombinator(variables, r.Body, r.Expressions, facts).Combine()
	if err != nil {
		return err
	}
outer:
	for _, h := range combined {
		p := r.Head.Clone()
		for i, id := range p.IDs {
			k, ok := id.(Variable)
			if !ok {
				continue
			}
			v, ok := h[k]
			if !ok {
				return InvalidRuleError{r, k}
			}

			// prevent the rule from generating facts with forbidden IDs
			for _, f := range r.forbiddenIDs {
				if f.Equal(*v) {
					continue outer
				}
			}

			p.IDs[i] = *v
		}
		newFacts.Insert(Fact{p})
	}

	return nil
}

type Check struct {
	Queries []Rule
}

type FactSet []Fact

func (s *FactSet) Insert(f Fact) bool {
	for _, v := range *s {
		if v.Equal(f.Predicate) {
			return false
		}
	}
	*s = append(*s, f)
	return true
}

func (s *FactSet) InsertAll(facts []Fact) {
	for _, f := range facts {
		s.Insert(f)
	}
}

func (s *FactSet) Equal(x *FactSet) bool {
	if len(*s) != len(*x) {
		return false
	}
	for _, f1 := range *x {
		found := false
		for _, f2 := range *s {
			if f1.Predicate.Equal(f2.Predicate) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

type runLimits struct {
	maxFacts      int
	maxIterations int
	maxDuration   time.Duration
}

var defaultRunLimits = runLimits{
	maxFacts:      1000,
	maxIterations: 100,
	maxDuration:   2 * time.Millisecond,
}

var (
	ErrWorldRunLimitMaxFacts      = errors.New("datalog: world runtime limit: too many facts")
	ErrWorldRunLimitMaxIterations = errors.New("datalog: world runtime limit: too many iterations")
	ErrWorldRunLimitTimeout       = errors.New("datalog: world runtime limit: timeout")
)

type WorldOption func(w *World)

func WithMaxFacts(maxFacts int) WorldOption {
	return func(w *World) {
		w.runLimits.maxFacts = maxFacts
	}
}

func WithMaxIterations(maxIterations int) WorldOption {
	return func(w *World) {
		w.runLimits.maxIterations = maxIterations
	}
}

func WithMaxDuration(maxDuration time.Duration) WorldOption {
	return func(w *World) {
		w.runLimits.maxDuration = maxDuration
	}
}

type World struct {
	facts *FactSet
	rules []Rule

	runLimits runLimits
}

func NewWorld(opts ...WorldOption) *World {
	w := &World{
		facts:     &FactSet{},
		runLimits: defaultRunLimits,
	}

	for _, opt := range opts {
		opt(w)
	}

	return w
}

func (w *World) AddFact(f Fact) {
	w.facts.Insert(f)
}

func (w *World) Facts() *FactSet {
	return w.facts
}

func (w *World) AddRule(r Rule) {
	w.rules = append(w.rules, r)
}

// AddRuleWithForbiddenIDs adds a rule which cannot generate facts
// containing any of the forbiddenIDs
func (w *World) AddRuleWithForbiddenIDs(r Rule, forbiddenIDs ...ID) {
	r.forbiddenIDs = forbiddenIDs
	w.AddRule(r)
}

func (w *World) Rules() []Rule {
	return w.rules
}

func (w *World) Run() error {
	done := make(chan error)
	ctx, cancel := context.WithTimeout(context.Background(), w.runLimits.maxDuration)
	defer cancel()

	go func() {
		for i := 0; i < w.runLimits.maxIterations; i++ {
			select {
			case <-ctx.Done():
				return
			default:
				var newFacts FactSet
				for _, r := range w.rules {
					select {
					case <-ctx.Done():
						return
					default:
						if err := r.Apply(w.facts, &newFacts); err != nil {
							done <- err
							return
						}
					}
				}

				prevCount := len(*w.facts)
				w.facts.InsertAll([]Fact(newFacts))

				newCount := len(*w.facts)
				if newCount >= w.runLimits.maxFacts {
					done <- ErrWorldRunLimitMaxFacts
					return
				}

				// last iteration did not generate any new facts, so we can stop here
				if newCount == prevCount {
					done <- nil
					return
				}
			}
		}
		done <- ErrWorldRunLimitMaxIterations
	}()

	select {
	case <-ctx.Done():
		return ErrWorldRunLimitTimeout
	case err := <-done:
		return err
	}
}

func (w *World) Query(pred Predicate) *FactSet {
	res := &FactSet{}
	for _, f := range *w.facts {
		if f.Predicate.Name != pred.Name {
			continue
		}
		minLen := len(f.Predicate.IDs)
		if l := len(pred.IDs); l < minLen {
			minLen = l
		}
		for i := 0; i < minLen; i++ {
			fID := f.Predicate.IDs[i]
			pID := pred.IDs[i]
			if fID.Type() != IDTypeVariable && fID.Type() == pID.Type() {
				if fID != pID {
					continue
				}
			} else if fID.Type() != IDTypeSymbol && pID.Type() != IDTypeVariable {
				continue
			}
			res.Insert(f)
		}
	}
	return res
}

func (w *World) QueryRule(rule Rule) *FactSet {
	newFacts := &FactSet{}
	rule.Apply(w.facts, newFacts)
	return newFacts
}

func (w *World) Clone() *World {
	newFacts := new(FactSet)
	*newFacts = *w.facts
	return &World{
		facts:     newFacts,
		rules:     append([]Rule{}, w.rules...),
		runLimits: w.runLimits,
	}
}

type MatchedVariables map[Variable]*ID

func (m MatchedVariables) Insert(k Variable, v ID) bool {
	existing := m[k]
	if existing == nil {
		m[k] = &v
		return true
	}
	return v.Equal(*existing)
}

func (m MatchedVariables) Complete() map[Variable]*ID {
	for _, v := range m {
		if v == nil {
			return nil
		}
	}
	return (map[Variable]*ID)(m)
}

func (m MatchedVariables) Clone() MatchedVariables {
	res := make(MatchedVariables, len(m))
	for k, v := range m {
		res[k] = v
	}
	return res
}

type Combinator struct {
	variables    MatchedVariables
	predicates   []Predicate
	expressions  []Expression
	allFacts     *FactSet
	currentFacts *FactSet
}

func NewCombinator(variables MatchedVariables, predicates []Predicate, expressions []Expression, allFacts *FactSet) *Combinator {
	c := &Combinator{
		variables:   variables,
		predicates:  predicates,
		expressions: expressions,
		allFacts:    allFacts,
	}
	currentFacts := make(FactSet, 0, len(*allFacts))
	for _, f := range *allFacts {
		if len(predicates) > 0 && f.Match(predicates[0]) {
			currentFacts = append(currentFacts, f)
		}
	}
	c.currentFacts = &currentFacts
	return c
}

func (c *Combinator) Combine() ([]map[Variable]*ID, error) {
	var variables []map[Variable]*ID
	// Stop when no more predicates are available
	if len(c.predicates) == 0 {
		if vars := c.variables.Complete(); vars != nil {
			variables = append(variables, vars)
		}
		return variables, nil
	}

	for i, pred := range c.predicates {
		for ii, currentFact := range *c.currentFacts {
			vars := c.variables.Clone()
			matchIDs := true
			// minLen is the smallest number of IDs
			// between the predicate and the current fact
			minLen := len(pred.IDs)
			if l := len(currentFact.Predicate.IDs); l < minLen {
				minLen = l
			}

			for j := 0; j < minLen; j++ {
				id := pred.IDs[j]
				k, ok := id.(Variable)
				if !ok {
					continue
				}
				v := currentFact.Predicate.IDs[j]
				if !vars.Insert(k, v) {
					matchIDs = false
				}
				if !matchIDs {
					break
				}
			}

			if !matchIDs {
				continue
			}

			if len(c.predicates) > i+1 {
				next, err := NewCombinator(vars, c.predicates[i+1:], c.expressions, c.allFacts).Combine()
				if err != nil {
					return nil, err
				}
				if len(next) == 0 {
					// returns only if there is no more current facts, otherwise process next one
					if ii == len(*c.currentFacts)-1 {
						return variables, nil
					}
					continue
				}
				variables = append(variables, next...)
			} else {
				if v := vars.Complete(); v != nil {
					valid := true
					for _, e := range c.expressions {
						res, err := e.Evaluate(v)
						if err != nil {
							return nil, err
						}
						if !res.Equal(Bool(true)) {
							valid = false
							break
						}
					}

					if valid {
						variables = append(variables, v)
					}
				}
			}
		}
	}
	return variables, nil
}

type SymbolTable []string

func (t *SymbolTable) Insert(s string) Symbol {
	for i, v := range *t {
		if string(v) == s {
			return Symbol(i)
		}
	}
	*t = append(*t, s)
	return Symbol(len(*t) - 1)
}

func (t *SymbolTable) Sym(s string) ID {
	for i, v := range *t {
		if string(v) == s {
			return Symbol(i)
		}
	}
	return nil
}

func (t *SymbolTable) Str(sym Symbol) string {
	if int(sym) > len(*t)-1 {
		return fmt.Sprintf("<invalid symbol %d>", sym)
	}
	return (*t)[int(sym)]
}

func (t *SymbolTable) Clone() *SymbolTable {
	newTable := *t
	return &newTable
}

// SplitOff returns a newly allocated slice containing the elements in the range
// [at, len). After the call, the receiver will be left containing
// the elements [0, at) with its previous capacity unchanged.
func (t *SymbolTable) SplitOff(at int) *SymbolTable {
	if at > len(*t) {
		panic("split index out of bound")
	}

	new := make(SymbolTable, len(*t)-at)
	copy(new, (*t)[at:])

	*t = (*t)[:at]

	return &new
}

func (t *SymbolTable) Len() int {
	return len(*t)
}

// IsDisjoint returns true if receiver has no elements in common with other.
// This is equivalent to checking for an empty intersection.
func (t *SymbolTable) IsDisjoint(other *SymbolTable) bool {
	m := make(map[string]struct{}, len(*t))
	for _, s := range *t {
		m[s] = struct{}{}
	}

	for _, os := range *other {
		if _, ok := m[os]; ok {
			return false
		}
	}

	return true
}

// Extend insert symbols from the given SymbolTable in the receiving one
// excluding any Symbols already existing
func (t *SymbolTable) Extend(other *SymbolTable) {
	for _, s := range *other {
		t.Insert(s)
	}
}

type SymbolDebugger struct {
	*SymbolTable
}

func (d SymbolDebugger) Predicate(p Predicate) string {
	strs := make([]string, len(p.IDs))
	for i, id := range p.IDs {
		var s string
		if sym, ok := id.(Symbol); ok {
			s = "#" + d.Str(sym)
		} else {
			s = fmt.Sprintf("%v", id)
		}
		strs[i] = s
	}
	return fmt.Sprintf("%s(%s)", d.Str(p.Name), strings.Join(strs, ", "))
}

func (d SymbolDebugger) Rule(r Rule) string {
	head := d.Predicate(r.Head)
	preds := make([]string, len(r.Body))
	for i, p := range r.Body {
		preds[i] = d.Predicate(p)
	}
	expressions := make([]string, len(r.Expressions))
	for i, e := range r.Expressions {
		expressions[i] = d.Expression(e)
	}

	var expressionsStart string
	if len(expressions) > 0 {
		expressionsStart = " @ "
	}

	return fmt.Sprintf("*%s <- %s%s%s", head, strings.Join(preds, ", "), expressionsStart, strings.Join(expressions, ", "))
}

func (d SymbolDebugger) Expression(e Expression) string {
	return e.Print(d.SymbolTable)
}

func (d SymbolDebugger) Check(c Check) string {
	queries := make([]string, len(c.Queries))
	for i, q := range c.Queries {
		queries[i] = d.Rule(q)
	}
	return strings.Join(queries, " || ")
}

func (d SymbolDebugger) World(w *World) string {
	facts := make([]string, len(*w.facts))
	for i, f := range *w.facts {
		facts[i] = d.Predicate(f.Predicate)
	}
	rules := make([]string, len(w.rules))
	for i, r := range w.rules {
		rules[i] = d.Rule(r)
	}
	return fmt.Sprintf("World {{\n\tfacts: %v\n\trules: %v\n}}", facts, rules)
}

func (d SymbolDebugger) FactSet(s *FactSet) string {
	strs := make([]string, len(*s))
	for i, f := range *s {
		strs[i] = d.Predicate(f.Predicate)
	}
	return fmt.Sprintf("%v", strs)
}
