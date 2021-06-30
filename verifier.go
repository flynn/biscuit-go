package biscuit

import (
	"errors"
	"fmt"
	"strings"

	"github.com/biscuit-auth/biscuit-go/datalog"
	"github.com/biscuit-auth/biscuit-go/pb"
	"google.golang.org/protobuf/proto"
)

var (
	ErrMissingSymbols   = errors.New("biscuit: missing symbols")
	ErrPolicyDenied     = errors.New("biscuit: denied by policy")
	ErrNoMatchingPolicy = errors.New("biscuit: denied by no matching policies")
)

type Verifier interface {
	AddFact(fact Fact)
	AddRule(rule Rule)
	AddCheck(check Check)
	AddPolicy(policy Policy)
	Verify() error
	Query(rule Rule) (FactSet, error)
	Biscuit() *Biscuit
	Reset()
	PrintWorld() string
	LoadPolicies([]byte) error
	SerializePolicies() ([]byte, error)
}

type verifier struct {
	biscuit     *Biscuit
	baseWorld   *datalog.World
	baseSymbols *datalog.SymbolTable
	world       *datalog.World
	symbols     *datalog.SymbolTable

	checks   []Check
	policies []Policy

	dirty bool
}

var _ Verifier = (*verifier)(nil)

func NewVerifier(b *Biscuit) (Verifier, error) {
	baseWorld, err := b.generateWorld(b.symbols)
	if err != nil {
		return nil, err
	}

	return &verifier{
		biscuit:     b,
		baseWorld:   baseWorld,
		baseSymbols: b.symbols.Clone(),
		world:       baseWorld.Clone(),
		symbols:     b.symbols.Clone(),
		checks:      []Check{},
	}, nil
}

func (v *verifier) AddFact(fact Fact) {
	v.world.AddFact(fact.convert(v.symbols))
}

func (v *verifier) AddRule(rule Rule) {
	v.world.AddRule(rule.convert(v.symbols))
}

func (v *verifier) AddCheck(check Check) {
	v.checks = append(v.checks, check)
}

func (v *verifier) AddPolicy(policy Policy) {
	v.policies = append(v.policies, policy)
}

func (v *verifier) Verify() error {
	debug := datalog.SymbolDebugger{
		SymbolTable: v.symbols,
	}

	if v.symbols.Sym("authority") == nil || v.symbols.Sym("ambient") == nil {
		return ErrMissingSymbols
	}

	if err := v.world.Run(); err != nil {
		return err
	}
	v.dirty = true

	var errs []error

	for i, check := range v.checks {
		c := check.convert(v.symbols)
		successful := false
		for _, query := range c.Queries {
			res := v.world.QueryRule(query)
			if len(*res) != 0 {
				successful = true
				break
			}
		}
		if !successful {
			errs = append(errs, fmt.Errorf("failed to verify check #%d: %s", i, debug.Check(c)))
		}
	}

	for bi, blockChecks := range v.biscuit.Checks() {
		for ci, check := range blockChecks {
			successful := false
			for _, query := range check.Queries {
				res := v.world.QueryRule(query)
				if len(*res) != 0 {
					successful = true
					break
				}
			}
			if !successful {
				errs = append(errs, fmt.Errorf("failed to verify block #%d check #%d: %s", bi, ci, debug.Check(check)))
			}
		}
	}

	if len(errs) > 0 {
		errMsg := make([]string, len(errs))
		for i, e := range errs {
			errMsg[i] = e.Error()
		}
		return fmt.Errorf("biscuit: verification failed: %s", strings.Join(errMsg, ", "))
	}

	for _, policy := range v.policies {
		for _, query := range policy.Queries {
			res := v.world.QueryRule(query.convert(v.symbols))
			if len(*res) != 0 {
				switch policy.Kind {
				case PolicyKindAllow:
					return nil
				case PolicyKindDeny:
					return ErrPolicyDenied
				}
			}
		}
	}

	return ErrNoMatchingPolicy
}

func (v *verifier) Query(rule Rule) (FactSet, error) {
	if err := v.world.Run(); err != nil {
		return nil, err
	}
	v.dirty = true

	facts := v.world.QueryRule(rule.convert(v.symbols))

	result := make([]Fact, 0, len(*facts))
	for _, fact := range *facts {
		f, err := fromDatalogFact(v.symbols, fact)
		if err != nil {
			return nil, err
		}

		result = append(result, *f)
	}

	return result, nil
}

func (v *verifier) Biscuit() *Biscuit {
	return v.biscuit
}

func (v *verifier) PrintWorld() string {
	debug := datalog.SymbolDebugger{
		SymbolTable: v.symbols,
	}

	return debug.World(v.world)
}

func (v *verifier) Reset() {
	v.world = v.baseWorld.Clone()
	v.symbols = v.baseSymbols.Clone()
	v.checks = []Check{}
	v.policies = []Policy{}
	v.dirty = false
}

func (v *verifier) LoadPolicies(verifierPolicies []byte) error {
	pbPolicies := &pb.VerifierPolicies{}
	if err := proto.Unmarshal(verifierPolicies, pbPolicies); err != nil {
		return fmt.Errorf("verifier: failed to load policies: %w", err)
	}

	switch pbPolicies.Version {
	case 1:
		return v.loadPoliciesV1(pbPolicies)
	default:
		return fmt.Errorf("verifier: unsupported policies version %d", pbPolicies.Version)
	}
}

func (v *verifier) loadPoliciesV1(pbPolicies *pb.VerifierPolicies) error {
	policySymbolTable := datalog.SymbolTable(pbPolicies.Symbols)
	v.symbols = v.baseSymbols.Clone()
	v.symbols.Extend(&policySymbolTable)

	for _, pbFact := range pbPolicies.Facts {
		fact, err := protoFactToTokenFactV1(pbFact)
		if err != nil {
			return fmt.Errorf("verifier: load policies v1: failed to convert datalog fact: %w", err)
		}
		v.world.AddFact(*fact)
	}

	for _, pbRule := range pbPolicies.Rules {
		rule, err := protoRuleToTokenRuleV1(pbRule)
		if err != nil {
			return fmt.Errorf("verifier: load policies v1: failed to convert datalog rule: %w", err)
		}
		v.world.AddRule(*rule)
	}

	v.checks = make([]Check, len(pbPolicies.Checks))
	for i, pbCheck := range pbPolicies.Checks {
		dlCheck, err := protoCheckToTokenCheckV1(pbCheck)
		if err != nil {
			return fmt.Errorf("verifier: load policies v1: failed to convert datalog check: %w", err)
		}
		check, err := fromDatalogCheck(v.symbols, *dlCheck)
		if err != nil {
			return fmt.Errorf("verifier: load policies v1: failed to convert check: %w", err)
		}
		v.checks[i] = *check
	}

	v.policies = make([]Policy, len(pbPolicies.Policies))
	for i, pbPolicy := range pbPolicies.Policies {
		policy := Policy{}
		switch pbPolicy.Kind {
		case pb.Policy_Allow:
			policy.Kind = PolicyKindAllow
		case pb.Policy_Deny:
			policy.Kind = PolicyKindDeny
		default:
			return fmt.Errorf("verifier: load policies v1: unsupported proto policy kind %v", pbPolicy.Kind)
		}

		policy.Queries = make([]Rule, len(pbPolicy.Queries))
		for j, pbRule := range pbPolicy.Queries {
			dlRule, err := protoRuleToTokenRuleV1(pbRule)
			if err != nil {
				return fmt.Errorf("verifier: load policies v1: failed to convert datalog policy rule: %w", err)
			}

			rule, err := fromDatalogRule(v.symbols, *dlRule)
			if err != nil {
				return fmt.Errorf("verifier: load policies v1: failed to convert policy rule: %w", err)
			}
			policy.Queries[j] = *rule
		}
		v.policies[i] = policy
	}

	return nil
}

func (v *verifier) SerializePolicies() ([]byte, error) {
	if v.dirty {
		return nil, errors.New("verifier: can't serialize after world has been run")
	}

	protoFacts := make([]*pb.FactV1, len(*v.world.Facts()))
	for i, fact := range *v.world.Facts() {
		protoFact, err := tokenFactToProtoFactV1(fact)
		if err != nil {
			return nil, fmt.Errorf("verifier: failed to convert fact: %w", err)
		}
		protoFacts[i] = protoFact
	}

	protoRules := make([]*pb.RuleV1, len(v.world.Rules()))
	for i, rule := range v.world.Rules() {
		protoRule, err := tokenRuleToProtoRuleV1(rule)
		if err != nil {
			return nil, fmt.Errorf("verifier: failed to convert rule: %w", err)
		}
		protoRules[i] = protoRule
	}

	protoChecks := make([]*pb.CheckV1, len(v.checks))
	for i, check := range v.checks {
		protoCheck, err := tokenCheckToProtoCheckV1(check.convert(v.symbols))
		if err != nil {
			return nil, fmt.Errorf("verifier: failed to convert check: %w", err)
		}
		protoChecks[i] = protoCheck
	}

	protoPolicies := make([]*pb.Policy, len(v.policies))
	for i, policy := range v.policies {
		protoPolicy := &pb.Policy{}
		switch policy.Kind {
		case PolicyKindAllow:
			protoPolicy.Kind = pb.Policy_Allow
		case PolicyKindDeny:
			protoPolicy.Kind = pb.Policy_Deny
		default:
			return nil, fmt.Errorf("verifier: unsupported policy kind %v", policy.Kind)
		}

		protoPolicy.Queries = make([]*pb.RuleV1, len(policy.Queries))
		for j, rule := range policy.Queries {
			protoRule, err := tokenRuleToProtoRuleV1(rule.convert(v.symbols))
			if err != nil {
				return nil, fmt.Errorf("verifier: failed to convert policy rule: %w", err)
			}
			protoPolicy.Queries[j] = protoRule
		}

		protoPolicies[i] = protoPolicy
	}

	return proto.Marshal(&pb.VerifierPolicies{
		Symbols:  *v.symbols.Clone(),
		Version:  MaxSchemaVersion,
		Facts:    protoFacts,
		Rules:    protoRules,
		Checks:   protoChecks,
		Policies: protoPolicies,
	})
}
