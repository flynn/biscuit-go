package biscuit

import (
	"fmt"

	"github.com/biscuit-auth/biscuit-go/datalog"
	"github.com/biscuit-auth/biscuit-go/pb"
)

func protoFactToTokenFactV0(input *pb.FactV0) (*datalog.Fact, error) {
	pred, err := protoPredicateToTokenPredicateV0(input.Predicate)
	if err != nil {
		return nil, err
	}
	return &datalog.Fact{
		Predicate: *pred,
	}, nil
}

func protoPredicateToTokenPredicateV0(input *pb.PredicateV0) (*datalog.Predicate, error) {
	ids := make([]datalog.ID, len(input.Ids))
	for i, id := range input.Ids {
		dlid, err := protoIDToTokenIDV0(id)
		if err != nil {
			return nil, err
		}

		ids[i] = *dlid
	}

	return &datalog.Predicate{
		Name: datalog.Symbol(input.Name),
		IDs:  ids,
	}, nil
}

func protoIDToTokenIDV0(input *pb.IDV0) (*datalog.ID, error) {
	var id datalog.ID
	switch input.Kind {
	case pb.IDV0_STR:
		id = datalog.String(input.Str)
	case pb.IDV0_DATE:
		id = datalog.Date(input.Date)
	case pb.IDV0_INTEGER:
		id = datalog.Integer(input.Integer)
	case pb.IDV0_SYMBOL:
		id = datalog.Symbol(input.Symbol)
	case pb.IDV0_VARIABLE:
		id = datalog.Variable(input.Variable)
	case pb.IDV0_BYTES:
		id = datalog.Bytes(input.Bytes)
	default:
		return nil, fmt.Errorf("biscuit: failed to convert proto ID to token ID: unsupported id kind: %v", input.Kind)
	}

	return &id, nil
}

func protoRuleToTokenRuleV0(input *pb.RuleV0) (*datalog.Rule, error) {
	body := make([]datalog.Predicate, len(input.Body))
	for i, pb := range input.Body {
		b, err := protoPredicateToTokenPredicateV0(pb)
		if err != nil {
			return nil, err
		}
		body[i] = *b
	}

	expressions := make([]datalog.Expression, len(input.Constraints))
	for i, pbConstraint := range input.Constraints {
		expr, err := protoConstraintToTokenExprV0(pbConstraint)
		if err != nil {
			return nil, err
		}
		expressions[i] = expr
	}

	head, err := protoPredicateToTokenPredicateV0(input.Head)
	if err != nil {
		return nil, err
	}
	return &datalog.Rule{
		Head:        *head,
		Body:        body,
		Expressions: expressions,
	}, nil
}

func protoConstraintToTokenExprV0(input *pb.ConstraintV0) (datalog.Expression, error) {
	var expr datalog.Expression
	var err error
	switch input.Kind {
	case pb.ConstraintV0_DATE:
		expr, err = protoDateConstraintToTokenExprV0(input.Id, input.Date)
	case pb.ConstraintV0_INT:
		expr, err = protoIntConstraintToTokenExprV0(input.Id, input.Int)
	case pb.ConstraintV0_STRING:
		expr, err = protoStrConstraintToTokenExprV0(input.Id, input.Str)
	case pb.ConstraintV0_SYMBOL:
		expr, err = protoSymbolConstraintToTokenExprV0(input.Id, input.Symbol)
	case pb.ConstraintV0_BYTES:
		expr, err = protoBytesConstraintToTokenExprV0(input.Id, input.Bytes)
	default:
		err = fmt.Errorf("biscuit: unsupported constraint kind: %v", input.Kind)
	}
	return expr, err
}

func protoDateConstraintToTokenExprV0(id uint32, input *pb.DateConstraintV0) (datalog.Expression, error) {
	var expr datalog.Expression
	switch input.Kind {
	case pb.DateConstraintV0_BEFORE:
		expr = datalog.Expression{
			datalog.Value{ID: datalog.Variable(id)},
			datalog.Value{ID: datalog.Date(input.Before)},
			datalog.BinaryOp{BinaryOpFunc: datalog.LessOrEqual{}},
		}
	case pb.DateConstraintV0_AFTER:
		expr = datalog.Expression{
			datalog.Value{ID: datalog.Variable(id)},
			datalog.Value{ID: datalog.Date(input.After)},
			datalog.BinaryOp{BinaryOpFunc: datalog.GreaterOrEqual{}},
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported date constraint kind: %v", input.Kind)
	}
	return expr, nil
}

func protoIntConstraintToTokenExprV0(id uint32, input *pb.IntConstraintV0) (datalog.Expression, error) {
	var expr datalog.Expression
	switch input.Kind {
	case pb.IntConstraintV0_EQUAL:
		expr = datalog.Expression{
			datalog.Value{ID: datalog.Variable(id)},
			datalog.Value{ID: datalog.Integer(input.Equal)},
			datalog.BinaryOp{BinaryOpFunc: datalog.Equal{}},
		}
	case pb.IntConstraintV0_IN:
		set := make([]datalog.ID, len(input.InSet))
		for i, v := range input.InSet {
			set[i] = datalog.Integer(v)
		}
		expr = datalog.Expression{
			datalog.Value{ID: datalog.Set(set)},
			datalog.Value{ID: datalog.Variable(id)},
			datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
		}
	case pb.IntConstraintV0_NOT_IN:
		set := make([]datalog.ID, len(input.NotInSet))
		for i, v := range input.NotInSet {
			set[i] = datalog.Integer(v)
		}
		expr = datalog.Expression{
			datalog.Value{ID: datalog.Set(set)},
			datalog.Value{ID: datalog.Variable(id)},
			datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
			datalog.UnaryOp{UnaryOpFunc: datalog.Negate{}},
		}
	case pb.IntConstraintV0_LARGER:
		expr = datalog.Expression{
			datalog.Value{ID: datalog.Variable(id)},
			datalog.Value{ID: datalog.Integer(input.Larger)},
			datalog.BinaryOp{BinaryOpFunc: datalog.GreaterThan{}},
		}
	case pb.IntConstraintV0_LARGER_OR_EQUAL:
		expr = datalog.Expression{
			datalog.Value{ID: datalog.Variable(id)},
			datalog.Value{ID: datalog.Integer(input.LargerOrEqual)},
			datalog.BinaryOp{BinaryOpFunc: datalog.GreaterOrEqual{}},
		}
	case pb.IntConstraintV0_LOWER:
		expr = datalog.Expression{
			datalog.Value{ID: datalog.Variable(id)},
			datalog.Value{ID: datalog.Integer(input.Lower)},
			datalog.BinaryOp{BinaryOpFunc: datalog.LessThan{}},
		}
	case pb.IntConstraintV0_LOWER_OR_EQUAL:
		expr = datalog.Expression{
			datalog.Value{ID: datalog.Variable(id)},
			datalog.Value{ID: datalog.Integer(input.LowerOrEqual)},
			datalog.BinaryOp{BinaryOpFunc: datalog.LessOrEqual{}},
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported int constraint kind: %v", input.Kind)
	}
	return expr, nil
}

func protoStrConstraintToTokenExprV0(id uint32, input *pb.StringConstraintV0) (datalog.Expression, error) {
	var expr datalog.Expression
	switch input.Kind {
	case pb.StringConstraintV0_EQUAL:
		expr = datalog.Expression{
			datalog.Value{ID: datalog.Variable(id)},
			datalog.Value{ID: datalog.String(input.Equal)},
			datalog.BinaryOp{BinaryOpFunc: datalog.Equal{}},
		}
	case pb.StringConstraintV0_IN:
		set := make([]datalog.ID, len(input.InSet))
		for i, s := range input.InSet {
			set[i] = datalog.String(s)
		}
		expr = datalog.Expression{
			datalog.Value{ID: datalog.Set(set)},
			datalog.Value{ID: datalog.Variable(id)},
			datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
		}
	case pb.StringConstraintV0_NOT_IN:
		set := make([]datalog.ID, len(input.NotInSet))
		for i, s := range input.NotInSet {
			set[i] = datalog.String(s)
		}
		expr = datalog.Expression{
			datalog.Value{ID: datalog.Set(set)},
			datalog.Value{ID: datalog.Variable(id)},
			datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
			datalog.UnaryOp{UnaryOpFunc: datalog.Negate{}},
		}
	case pb.StringConstraintV0_PREFIX:
		expr = datalog.Expression{
			datalog.Value{ID: datalog.Variable(id)},
			datalog.Value{ID: datalog.String(input.Prefix)},
			datalog.BinaryOp{BinaryOpFunc: datalog.Prefix{}},
		}
	case pb.StringConstraintV0_REGEX:
		expr = datalog.Expression{
			datalog.Value{ID: datalog.Variable(id)},
			datalog.Value{ID: datalog.String(input.Regex)},
			datalog.BinaryOp{BinaryOpFunc: datalog.Regex{}},
		}
	case pb.StringConstraintV0_SUFFIX:
		expr = datalog.Expression{
			datalog.Value{ID: datalog.Variable(id)},
			datalog.Value{ID: datalog.String(input.Suffix)},
			datalog.BinaryOp{BinaryOpFunc: datalog.Suffix{}},
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported string constraint kind: %v", input.Kind)
	}

	return expr, nil
}

func protoSymbolConstraintToTokenExprV0(id uint32, input *pb.SymbolConstraintV0) (datalog.Expression, error) {
	var expr datalog.Expression
	switch input.Kind {
	case pb.SymbolConstraintV0_IN:
		set := make([]datalog.ID, len(input.InSet))
		for i, s := range input.InSet {
			set[i] = datalog.Symbol(s)
		}
		expr = datalog.Expression{
			datalog.Value{ID: datalog.Set(set)},
			datalog.Value{ID: datalog.Variable(id)},
			datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
		}
	case pb.SymbolConstraintV0_NOT_IN:
		set := make([]datalog.ID, len(input.NotInSet))
		for i, s := range input.NotInSet {
			set[i] = datalog.Symbol(s)
		}
		expr = datalog.Expression{
			datalog.Value{ID: datalog.Set(set)},
			datalog.Value{ID: datalog.Variable(id)},
			datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
			datalog.UnaryOp{UnaryOpFunc: datalog.Negate{}},
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported symbol constraint kind: %v", input.Kind)
	}
	return expr, nil
}

func protoBytesConstraintToTokenExprV0(id uint32, input *pb.BytesConstraintV0) (datalog.Expression, error) {
	var expr datalog.Expression
	switch input.Kind {
	case pb.BytesConstraintV0_EQUAL:
		expr = datalog.Expression{
			datalog.Value{ID: datalog.Variable(id)},
			datalog.Value{ID: datalog.Bytes(input.Equal)},
			datalog.BinaryOp{BinaryOpFunc: datalog.Equal{}},
		}
	case pb.BytesConstraintV0_IN:
		set := make([]datalog.ID, len(input.InSet))
		for i, s := range input.InSet {
			set[i] = datalog.Bytes(s)
		}
		expr = datalog.Expression{
			datalog.Value{ID: datalog.Set(set)},
			datalog.Value{ID: datalog.Variable(id)},
			datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
		}
	case pb.BytesConstraintV0_NOT_IN:
		set := make([]datalog.ID, len(input.NotInSet))
		for i, s := range input.NotInSet {
			set[i] = datalog.Bytes(s)
		}
		expr = datalog.Expression{
			datalog.Value{ID: datalog.Set(set)},
			datalog.Value{ID: datalog.Variable(id)},
			datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
			datalog.UnaryOp{UnaryOpFunc: datalog.Negate{}},
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported bytes constraint kind: %v", input.Kind)
	}

	return expr, nil
}

func protoCaveatToTokenCheckV0(input *pb.CaveatV0) (*datalog.Check, error) {
	queries := make([]datalog.Rule, len(input.Queries))
	for i, query := range input.Queries {
		q, err := protoRuleToTokenRuleV0(query)
		if err != nil {
			return nil, err
		}
		queries[i] = *q
	}

	return &datalog.Check{
		Queries: queries,
	}, nil
}
