package datalog

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func hashVar(s string) Variable {
	h := sha256.Sum256([]byte(s))
	id := uint32(h[0]) +
		uint32(h[1])<<8 +
		uint32(h[2])<<16 +
		uint32(h[3])<<24
	return Variable(id)
}

func TestFamily(t *testing.T) {
	w := NewWorld()
	syms := &SymbolTable{}
	dbg := SymbolDebugger{syms}
	a := syms.Insert("A")
	b := syms.Insert("B")
	c := syms.Insert("C")
	d := syms.Insert("D")
	e := syms.Insert("e")
	parent := syms.Insert("parent")
	grandparent := syms.Insert("grandparent")

	w.AddFact(Fact{Predicate{parent, []ID{a, b}}})
	w.AddFact(Fact{Predicate{parent, []ID{b, c}}})
	w.AddFact(Fact{Predicate{parent, []ID{c, d}}})

	r1 := Rule{
		Head: Predicate{grandparent, []ID{hashVar("grandparent"), hashVar("grandchild")}},
		Body: []Predicate{
			{parent, []ID{hashVar("grandparent"), hashVar("parent")}},
			{parent, []ID{hashVar("parent"), hashVar("grandchild")}},
		},
	}

	t.Logf("querying r1: %s", dbg.Rule(r1))
	queryRuleResult := w.QueryRule(r1)
	t.Logf("r1 query: %s", dbg.FactSet(queryRuleResult))
	t.Logf("current facts: %s", dbg.FactSet(w.facts))

	r2 := Rule{
		Head: Predicate{grandparent, []ID{hashVar("grandparent"), hashVar("grandchild")}},
		Body: []Predicate{
			{parent, []ID{hashVar("grandparent"), hashVar("parent")}},
			{parent, []ID{hashVar("parent"), hashVar("grandchild")}},
		},
	}

	t.Logf("adding r2: %s", dbg.Rule(r2))
	w.AddRule(r2)
	if err := w.Run(); err != nil {
		t.Error(err)
	}

	w.AddFact(Fact{Predicate{parent, []ID{c, e}}})
	if err := w.Run(); err != nil {
		t.Error(err)
	}

	res := w.Query(Predicate{grandparent, []ID{hashVar("grandparent"), hashVar("grandchild")}})
	t.Logf("grandparents after inserting parent(C, E): %s", dbg.FactSet(res))
	expected := &FactSet{
		Fact{Predicate{grandparent, []ID{a, c}}},
		Fact{Predicate{grandparent, []ID{b, d}}},
		Fact{Predicate{grandparent, []ID{b, e}}},
	}
	if !res.Equal(expected) {
		t.Errorf("unexpected result:\nhave %s\n want %s", dbg.FactSet(res), dbg.FactSet(expected))
	}
}

func TestNumbers(t *testing.T) {
	w := NewWorld()
	syms := &SymbolTable{}
	dbg := SymbolDebugger{syms}

	abc := syms.Insert("abc")
	def := syms.Insert("def")
	ghi := syms.Insert("ghi")
	jkl := syms.Insert("jkl")
	mno := syms.Insert("mno")
	aaa := syms.Insert("AAA")
	bbb := syms.Insert("BBB")
	ccc := syms.Insert("CCC")
	t1 := syms.Insert("t1")
	t2 := syms.Insert("t2")
	join := syms.Insert("join")

	w.AddFact(Fact{Predicate{t1, []ID{Integer(0), abc}}})
	w.AddFact(Fact{Predicate{t1, []ID{Integer(1), def}}})
	w.AddFact(Fact{Predicate{t1, []ID{Integer(2), ghi}}})
	w.AddFact(Fact{Predicate{t1, []ID{Integer(3), jkl}}})
	w.AddFact(Fact{Predicate{t1, []ID{Integer(4), mno}}})

	w.AddFact(Fact{Predicate{t2, []ID{Integer(0), aaa, Integer(0)}}})
	w.AddFact(Fact{Predicate{t2, []ID{Integer(1), bbb, Integer(0)}}})
	w.AddFact(Fact{Predicate{t2, []ID{Integer(2), ccc, Integer(1)}}})

	res := w.QueryRule(Rule{
		Head: Predicate{join, []ID{hashVar("left"), hashVar("right")}},
		Body: []Predicate{
			{t1, []ID{hashVar("id"), hashVar("left")}},
			{t2, []ID{hashVar("t2_id"), hashVar("right"), hashVar("id")}},
		},
	})
	expected := &FactSet{
		{Predicate{join, []ID{abc, aaa}}},
		{Predicate{join, []ID{abc, bbb}}},
		{Predicate{join, []ID{def, ccc}}},
	}
	if !expected.Equal(res) {
		t.Errorf("query failed:\n have: %s\n want: %s", dbg.FactSet(res), dbg.FactSet(expected))
	}

	res = w.QueryRule(Rule{
		Head: Predicate{join, []ID{hashVar("left"), hashVar("right")}},
		Body: []Predicate{
			{t1, []ID{Variable(1234), hashVar("left")}},
			{t2, []ID{hashVar("t2_id"), hashVar("right"), Variable(1234)}},
		},
		Expressions: []Expression{{
			Value{Variable(1234)},
			Value{Integer(1)},
			BinaryOp{LessThan{}},
		}},
	})
	expected = &FactSet{
		{Predicate{join, []ID{abc, aaa}}},
		{Predicate{join, []ID{abc, bbb}}},
	}
	if !expected.Equal(res) {
		t.Errorf("constraint query failed:\n have: %s\n want: %s", dbg.FactSet(res), dbg.FactSet(expected))
	}
}

func TestString(t *testing.T) {
	w := NewWorld()
	syms := &SymbolTable{}
	dbg := SymbolDebugger{syms}

	app0 := syms.Insert("app_0")
	app1 := syms.Insert("app_1")
	app2 := syms.Insert("app_2")
	route := syms.Insert("route")
	suff := syms.Insert("route suffix")

	w.AddFact(Fact{Predicate{route, []ID{Integer(0), app0, String("example.com")}}})
	w.AddFact(Fact{Predicate{route, []ID{Integer(1), app1, String("test.com")}}})
	w.AddFact(Fact{Predicate{route, []ID{Integer(2), app2, String("test.fr")}}})
	w.AddFact(Fact{Predicate{route, []ID{Integer(3), app0, String("www.example.com")}}})
	w.AddFact(Fact{Predicate{route, []ID{Integer(4), app1, String("mx.example.com")}}})

	testSuffix := func(suffix String) *FactSet {
		return w.QueryRule(Rule{
			Head: Predicate{suff, []ID{hashVar("app_id"), Variable(1234)}},
			Body: []Predicate{{route, []ID{Variable(0), hashVar("app_id"), Variable(1234)}}},
			Expressions: []Expression{{
				Value{Variable(1234)},
				Value{String(suffix)},
				BinaryOp{Suffix{}},
			}},
		})
	}

	res := testSuffix(".fr")
	expected := &FactSet{{Predicate{suff, []ID{app2, String("test.fr")}}}}
	if !expected.Equal(res) {
		t.Errorf(".fr suffix query failed:\n have: %s\n want: %s", dbg.FactSet(res), dbg.FactSet(expected))
	}

	res = testSuffix("example.com")
	expected = &FactSet{
		{Predicate{suff, []ID{app0, String("example.com")}}},
		{Predicate{suff, []ID{app0, String("www.example.com")}}},
		{Predicate{suff, []ID{app1, String("mx.example.com")}}},
	}
	if !expected.Equal(res) {
		t.Errorf("example.com suffix query failed:\n have: %s\n want: %s", dbg.FactSet(res), dbg.FactSet(expected))
	}
}

func TestDate(t *testing.T) {
	w := NewWorld()
	syms := &SymbolTable{}
	dbg := SymbolDebugger{syms}

	t1 := time.Unix(1, 0)
	t2 := t1.Add(10 * time.Second)
	t3 := t2.Add(30 * time.Second)

	abc := syms.Insert("abc")
	def := syms.Insert("def")
	x := syms.Insert("x")
	before := syms.Insert("before")
	after := syms.Insert("after")

	w.AddFact(Fact{Predicate{x, []ID{Date(t1.Unix()), abc}}})
	w.AddFact(Fact{Predicate{x, []ID{Date(t3.Unix()), def}}})

	res := w.QueryRule(Rule{
		Head: Predicate{before, []ID{Variable(1234), hashVar("val")}},
		Body: []Predicate{{x, []ID{Variable(1234), hashVar("val")}}},
		Expressions: []Expression{{
			Value{Variable(1234)},
			Value{Date(t2.Unix())},
			BinaryOp{LessOrEqual{}},
		}, {
			Value{Variable(1234)},
			Value{Date(0)},
			BinaryOp{GreaterOrEqual{}},
		}},
	})
	expected := &FactSet{{Predicate{before, []ID{Date(t1.Unix()), abc}}}}
	if !expected.Equal(res) {
		t.Errorf("before query failed:\n have: %s\n want: %s", dbg.FactSet(res), dbg.FactSet(expected))
	}

	res = w.QueryRule(Rule{
		Head: Predicate{after, []ID{Variable(1234), hashVar("val")}},
		Body: []Predicate{{x, []ID{Variable(1234), hashVar("val")}}},
		Expressions: []Expression{{
			Value{Variable(1234)},
			Value{Date(t2.Unix())},
			BinaryOp{GreaterOrEqual{}},
		}, {
			Value{Variable(1234)},
			Value{Date(0)},
			BinaryOp{GreaterOrEqual{}},
		}},
	})
	expected = &FactSet{{Predicate{after, []ID{Date(t3.Unix()), def}}}}
	if !expected.Equal(res) {
		t.Errorf("before query failed:\n have: %s\n want: %s", dbg.FactSet(res), dbg.FactSet(expected))
	}
}

func TestBytes(t *testing.T) {
	w := NewWorld()
	syms := &SymbolTable{}
	dbg := SymbolDebugger{syms}

	k1 := make([]byte, 32)
	_, err := rand.Read(k1)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	k2 := make([]byte, 32)
	_, err = rand.Read(k2)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	k3 := make([]byte, 64)
	_, err = rand.Read(k3)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	usr1 := syms.Insert("usr1")
	usr2 := syms.Insert("usr2")
	usr3 := syms.Insert("usr3")

	key := syms.Insert("pkey")
	keyMatch := syms.Insert("pkey match")

	w.AddFact(Fact{Predicate{key, []ID{usr1, Bytes(k1)}}})
	w.AddFact(Fact{Predicate{key, []ID{usr2, Bytes(k2)}}})
	w.AddFact(Fact{Predicate{key, []ID{usr3, Bytes(k3)}}})

	res := w.QueryRule(Rule{
		Head: Predicate{keyMatch, []ID{hashVar("usr"), Variable(1)}},
		Body: []Predicate{{key, []ID{hashVar("usr"), Variable(1)}}},
		Expressions: []Expression{{
			Value{Variable(1)},
			Value{Bytes(k1)},
			BinaryOp{Equal{}},
		}},
	})
	expected := &FactSet{
		{Predicate{keyMatch, []ID{usr1, Bytes(k1)}}},
	}
	if !expected.Equal(res) {
		t.Errorf("key equal query failed:\n have: %s\n want: %s", dbg.FactSet(res), dbg.FactSet(expected))
	}

	res = w.QueryRule(Rule{
		Head: Predicate{keyMatch, []ID{hashVar("usr"), Variable(1)}},
		Body: []Predicate{{key, []ID{hashVar("usr"), Variable(1)}}},
		Expressions: []Expression{{
			Value{Set{Bytes(k1), Bytes(k3)}},
			Value{Variable(1)},
			BinaryOp{Contains{}},
		}},
	})
	expected = &FactSet{
		{Predicate{keyMatch, []ID{usr1, Bytes(k1)}}},
		{Predicate{keyMatch, []ID{usr3, Bytes(k3)}}},
	}
	if !expected.Equal(res) {
		t.Errorf("key in query failed:\n have: %s\n want: %s", dbg.FactSet(res), dbg.FactSet(expected))
	}

	res = w.QueryRule(Rule{
		Head: Predicate{keyMatch, []ID{hashVar("usr"), Variable(1)}},
		Body: []Predicate{{key, []ID{hashVar("usr"), Variable(1)}}},
		Expressions: []Expression{{
			Value{Set{Bytes(k1)}},
			Value{Variable(1)},
			BinaryOp{Contains{}},
			UnaryOp{Negate{}},
		}},
	})
	expected = &FactSet{
		{Predicate{keyMatch, []ID{usr2, Bytes(k2)}}},
		{Predicate{keyMatch, []ID{usr3, Bytes(k3)}}},
	}
	if !expected.Equal(res) {
		t.Errorf("key not in query failed:\n have: %s\n want: %s", dbg.FactSet(res), dbg.FactSet(expected))
	}
}

func TestResource(t *testing.T) {
	w := NewWorld()
	syms := &SymbolTable{}
	dbg := SymbolDebugger{syms}

	authority := syms.Insert("authority")
	ambient := syms.Insert("ambient")
	resource := syms.Insert("resource")
	operation := syms.Insert("operation")
	right := syms.Insert("right")
	file1 := syms.Insert("file1")
	file2 := syms.Insert("file2")
	read := syms.Insert("read")
	write := syms.Insert("write")

	w.AddFact(Fact{Predicate{resource, []ID{ambient, file2}}})
	w.AddFact(Fact{Predicate{operation, []ID{ambient, write}}})
	w.AddFact(Fact{Predicate{right, []ID{authority, file1, read}}})
	w.AddFact(Fact{Predicate{right, []ID{authority, file2, read}}})
	w.AddFact(Fact{Predicate{right, []ID{authority, file1, write}}})

	check1 := syms.Insert("check1")
	res := w.QueryRule(Rule{
		Head: Predicate{check1, []ID{file1}},
		Body: []Predicate{{resource, []ID{ambient, file1}}},
	})
	if len(*res) > 0 {
		t.Errorf("unexpected facts: %s", dbg.FactSet(res))
	}

	check2 := syms.Insert("check2")
	var0 := Variable(0)
	r2 := Rule{
		Head: Predicate{check2, []ID{var0}},
		Body: []Predicate{
			{resource, []ID{ambient, var0}},
			{operation, []ID{ambient, read}},
			{right, []ID{authority, var0, read}},
		},
	}
	t.Logf("r2 = %s", dbg.Rule(r2))
	res = w.QueryRule(r2)
	if len(*res) > 0 {
		t.Errorf("unexpected facts: %s", dbg.FactSet(res))
	}
}

func TestSymbolTable(t *testing.T) {
	s1 := new(SymbolTable)
	s2 := &SymbolTable{"a", "b", "c"}
	s3 := &SymbolTable{"d", "e", "f"}

	require.True(t, s1.IsDisjoint(s2))
	s1.Extend(s2)
	require.False(t, s1.IsDisjoint(s2))
	require.Equal(t, s2, s1)
	s1.Extend(s3)
	require.Equal(t, SymbolTable(append(*s2, *s3...)), *s1)

	require.Equal(t, len(*s2)+len(*s3), s1.Len())

	new := s1.SplitOff(len(*s2))
	require.Equal(t, s3, new)
	require.Equal(t, s2, s1)
}

func TestSymbolTableInsertAndSym(t *testing.T) {
	s := new(SymbolTable)
	require.Equal(t, Symbol(0), s.Insert("a"))
	require.Equal(t, Symbol(1), s.Insert("b"))
	require.Equal(t, Symbol(2), s.Insert("c"))

	require.Equal(t, &SymbolTable{"a", "b", "c"}, s)

	require.Equal(t, Symbol(0), s.Insert("a"))
	require.Equal(t, Symbol(3), s.Insert("d"))

	require.Equal(t, &SymbolTable{"a", "b", "c", "d"}, s)

	require.Equal(t, Symbol(0), s.Sym("a"))
	require.Equal(t, Symbol(1), s.Sym("b"))
	require.Equal(t, Symbol(2), s.Sym("c"))
	require.Equal(t, Symbol(3), s.Sym("d"))
	require.Equal(t, nil, s.Sym("e"))
}

func TestSymbolTableClone(t *testing.T) {
	s := new(SymbolTable)

	s.Insert("a")
	s.Insert("b")
	s.Insert("c")

	s2 := s.Clone()
	s2.Insert("a")
	s2.Insert("d")
	s2.Insert("e")

	require.Equal(t, &SymbolTable{"a", "b", "c"}, s)
	require.Equal(t, &SymbolTable{"a", "b", "c", "d", "e"}, s2)
}

func TestSetEqual(t *testing.T) {
	testCases := []struct {
		desc  string
		s1    Set
		s2    Set
		equal bool
	}{
		{
			desc:  "equal with same values in same order",
			s1:    Set{String("a"), String("b"), String("c")},
			s2:    Set{String("a"), String("b"), String("c")},
			equal: true,
		},
		{
			desc:  "equal with same values different order",
			s1:    Set{String("a"), String("b"), String("c")},
			s2:    Set{String("b"), String("c"), String("a")},
			equal: true,
		},
		{
			desc:  "not equal when length mismatch",
			s1:    Set{String("a"), String("b"), String("c")},
			s2:    Set{String("a"), String("b")},
			equal: false,
		},
		{
			desc:  "not equal when length mismatch",
			s1:    Set{String("a"), String("b"), String("c")},
			s2:    Set{String("a"), String("b"), String("c"), String("d")},
			equal: false,
		},
		{
			desc:  "not equal when same length but different values",
			s1:    Set{String("a"), String("b"), String("c")},
			s2:    Set{String("a"), String("b"), String("d")},
			equal: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.desc, func(t *testing.T) {
			require.Equal(t, testCase.equal, testCase.s1.Equal(testCase.s2))
		})
	}
}

func TestWorldRunLimits(t *testing.T) {
	syms := &SymbolTable{}
	a := syms.Insert("A")
	b := syms.Insert("B")
	c := syms.Insert("C")
	d := syms.Insert("D")
	parent := syms.Insert("parent")
	grandparent := syms.Insert("grandparent")

	testCases := []struct {
		desc        string
		opts        []WorldOption
		expectedErr error
	}{
		{
			desc:        "valid defaults",
			expectedErr: nil,
		},
		{
			desc: "timeout",
			opts: []WorldOption{
				WithMaxDuration(0),
			},
			expectedErr: ErrWorldRunLimitTimeout,
		},
		{
			desc: "max iteration exceeded",
			opts: []WorldOption{
				WithMaxIterations(1),
			},
			expectedErr: ErrWorldRunLimitMaxIterations,
		},
		{
			desc: "max iteration ok",
			opts: []WorldOption{
				WithMaxIterations(2),
			},
			expectedErr: nil,
		},
		{
			desc: "max facts exceeded",
			opts: []WorldOption{
				WithMaxFacts(5),
			},
			expectedErr: ErrWorldRunLimitMaxFacts,
		},
		{
			desc: "max facts ok",
			opts: []WorldOption{
				WithMaxFacts(6),
			},
			expectedErr: nil,
		},
	}

	for _, tc := range testCases {
		w := NewWorld(tc.opts...)

		w.AddFact(Fact{Predicate{parent, []ID{a, b}}})
		w.AddFact(Fact{Predicate{parent, []ID{b, c}}})
		w.AddFact(Fact{Predicate{parent, []ID{c, d}}})

		r1 := Rule{
			Head: Predicate{grandparent, []ID{hashVar("grandparent"), hashVar("grandchild")}},
			Body: []Predicate{
				{parent, []ID{hashVar("grandparent"), hashVar("parent")}},
				{parent, []ID{hashVar("parent"), hashVar("grandchild")}},
			},
		}

		w.AddRule(r1)
		require.Equal(t, tc.expectedErr, w.Run())
	}
}
