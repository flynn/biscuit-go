package biscuit

import (
	"fmt"

	"github.com/biscuit-auth/biscuit-go/datalog"
	"github.com/biscuit-auth/biscuit-go/pb"
	"github.com/biscuit-auth/biscuit-go/sig"
)

func tokenBlockToProtoBlock(input *Block) (*pb.Block, error) {
	out := &pb.Block{
		Index:   input.index,
		Symbols: *input.symbols,
		Context: input.context,
		Version: input.version,
	}

	out.FactsV1 = make([]*pb.FactV1, len(*input.facts))
	var err error
	for i, fact := range *input.facts {
		out.FactsV1[i], err = tokenFactToProtoFactV1(fact)
		if err != nil {
			return nil, err
		}
	}

	out.RulesV1 = make([]*pb.RuleV1, len(input.rules))
	for i, rule := range input.rules {
		r, err := tokenRuleToProtoRuleV1(rule)
		if err != nil {
			return nil, err
		}
		out.RulesV1[i] = r
	}

	out.ChecksV1 = make([]*pb.CheckV1, len(input.checks))
	for i, check := range input.checks {
		c, err := tokenCheckToProtoCheckV1(check)
		if err != nil {
			return nil, err
		}
		out.ChecksV1[i] = c
	}

	return out, nil
}

func protoBlockToTokenBlock(input *pb.Block) (*Block, error) {
	symbols := datalog.SymbolTable(input.Symbols)

	var facts datalog.FactSet
	var rules []datalog.Rule
	var checks []datalog.Check

	if input.Version > MaxSchemaVersion {
		return nil, fmt.Errorf(
			"biscuit: failed to convert proto block to token block: block version: %d > library version %d",
			input.Version,
			MaxSchemaVersion,
		)
	}

	switch input.Version {
	case 0:
		facts = make(datalog.FactSet, len(input.FactsV0))
		rules = make([]datalog.Rule, len(input.RulesV0))
		checks = make([]datalog.Check, len(input.CaveatsV0))

		for i, pbFact := range input.FactsV0 {
			f, err := protoFactToTokenFactV0(pbFact)
			if err != nil {
				return nil, err
			}
			facts[i] = *f
		}

		for i, pbRule := range input.RulesV0 {
			r, err := protoRuleToTokenRuleV0(pbRule)
			if err != nil {
				return nil, err
			}
			rules[i] = *r
		}

		for i, pbCaveat := range input.CaveatsV0 {
			c, err := protoCaveatToTokenCheckV0(pbCaveat)
			if err != nil {
				return nil, err
			}
			checks[i] = *c
		}
	case 1:
		facts = make(datalog.FactSet, len(input.FactsV1))
		rules = make([]datalog.Rule, len(input.RulesV1))
		checks = make([]datalog.Check, len(input.ChecksV1))

		for i, pbFact := range input.FactsV1 {
			f, err := protoFactToTokenFactV1(pbFact)
			if err != nil {
				return nil, err
			}
			facts[i] = *f
		}

		for i, pbRule := range input.RulesV1 {
			r, err := protoRuleToTokenRuleV1(pbRule)
			if err != nil {
				return nil, err
			}
			rules[i] = *r
		}

		for i, pbCheck := range input.ChecksV1 {
			c, err := protoCheckToTokenCheckV1(pbCheck)
			if err != nil {
				return nil, err
			}
			checks[i] = *c
		}
	default:
		return nil, fmt.Errorf("biscuit: failed to convert proto block to token block: unsupported version: %d", input.Version)
	}

	return &Block{
		index:   input.Index,
		symbols: &symbols,
		facts:   &facts,
		rules:   rules,
		checks:  checks,
		context: input.Context,
		version: input.Version,
	}, nil
}

func tokenSignatureToProtoSignature(ts *sig.TokenSignature) *pb.Signature {
	params, z := ts.Encode()
	return &pb.Signature{
		Parameters: params,
		Z:          z,
	}
}

func protoSignatureToTokenSignature(ps *pb.Signature) (*sig.TokenSignature, error) {
	return sig.Decode(ps.Parameters, ps.Z)
}
