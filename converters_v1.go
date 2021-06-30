package biscuit

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/biscuit-auth/biscuit-go/datalog"
	"github.com/biscuit-auth/biscuit-go/pb"
)

func tokenFactToProtoFactV1(input datalog.Fact) (*pb.FactV1, error) {
	pred, err := tokenPredicateToProtoPredicateV1(input.Predicate)
	if err != nil {
		return nil, err
	}

	return &pb.FactV1{
		Predicate: pred,
	}, nil
}

func protoFactToTokenFactV1(input *pb.FactV1) (*datalog.Fact, error) {
	pred, err := protoPredicateToTokenPredicateV1(input.Predicate)
	if err != nil {
		return nil, err
	}
	return &datalog.Fact{
		Predicate: *pred,
	}, nil
}

func tokenPredicateToProtoPredicateV1(input datalog.Predicate) (*pb.PredicateV1, error) {
	pbIds := make([]*pb.IDV1, len(input.IDs))
	var err error
	for i, id := range input.IDs {
		pbIds[i], err = tokenIDToProtoIDV1(id)
		if err != nil {
			return nil, err
		}
	}

	return &pb.PredicateV1{
		Name: uint64(input.Name),
		Ids:  pbIds,
	}, nil
}

func protoPredicateToTokenPredicateV1(input *pb.PredicateV1) (*datalog.Predicate, error) {
	ids := make([]datalog.ID, len(input.Ids))
	for i, id := range input.Ids {
		dlid, err := protoIDToTokenIDV1(id)
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

func tokenIDToProtoIDV1(input datalog.ID) (*pb.IDV1, error) {
	var pbId *pb.IDV1
	switch input.Type() {
	case datalog.IDTypeString:
		pbId = &pb.IDV1{
			Content: &pb.IDV1_Str{Str: string(input.(datalog.String))},
		}
	case datalog.IDTypeDate:
		pbId = &pb.IDV1{
			Content: &pb.IDV1_Date{Date: uint64(input.(datalog.Date))},
		}
	case datalog.IDTypeInteger:
		pbId = &pb.IDV1{
			Content: &pb.IDV1_Integer{Integer: int64(input.(datalog.Integer))},
		}
	case datalog.IDTypeSymbol:
		pbId = &pb.IDV1{
			Content: &pb.IDV1_Symbol{Symbol: uint64(input.(datalog.Symbol))},
		}
	case datalog.IDTypeVariable:
		pbId = &pb.IDV1{
			Content: &pb.IDV1_Variable{Variable: uint32(input.(datalog.Variable))},
		}
	case datalog.IDTypeBytes:
		pbId = &pb.IDV1{
			Content: &pb.IDV1_Bytes{Bytes: input.(datalog.Bytes)},
		}
	case datalog.IDTypeBool:
		pbId = &pb.IDV1{
			Content: &pb.IDV1_Bool{Bool: bool(input.(datalog.Bool))},
		}
	case datalog.IDTypeSet:
		datalogSet := input.(datalog.Set)
		if len(datalogSet) == 0 {
			return nil, errors.New("biscuit: failed to convert token ID to proto ID: set cannot be empty")
		}

		expectedEltType := datalogSet[0].Type()
		switch expectedEltType {
		case datalog.IDTypeVariable:
			return nil, errors.New("biscuit: failed to convert token ID to proto ID: set cannot contains variable")
		case datalog.IDTypeSet:
			return nil, errors.New("biscuit: failed to convert token ID to proto ID: set cannot contains other sets")
		}

		protoSet := make([]*pb.IDV1, 0, len(datalogSet))
		for _, datalogElt := range datalogSet {
			if datalogElt.Type() != expectedEltType {
				return nil, fmt.Errorf(
					"biscuit: failed to convert token ID to proto ID: set elements must have the same type (got %x, want %x)",
					datalogElt.Type(),
					expectedEltType,
				)
			}

			protoElt, err := tokenIDToProtoIDV1(datalogElt)
			if err != nil {
				return nil, err
			}

			protoSet = append(protoSet, protoElt)
		}
		pbId = &pb.IDV1{
			Content: &pb.IDV1_Set{
				Set: &pb.IDSet{
					Set: protoSet,
				},
			},
		}
	default:
		return nil, fmt.Errorf("biscuit: failed to convert token ID to proto ID: unsupported id type: %v", input.Type())
	}
	return pbId, nil
}

func protoIDToTokenIDV1(input *pb.IDV1) (*datalog.ID, error) {
	var id datalog.ID
	switch input.Content.(type) {
	case *pb.IDV1_Str:
		id = datalog.String(input.GetStr())
	case *pb.IDV1_Date:
		id = datalog.Date(input.GetDate())
	case *pb.IDV1_Integer:
		id = datalog.Integer(input.GetInteger())
	case *pb.IDV1_Symbol:
		id = datalog.Symbol(input.GetSymbol())
	case *pb.IDV1_Variable:
		id = datalog.Variable(input.GetVariable())
	case *pb.IDV1_Bytes:
		id = datalog.Bytes(input.GetBytes())
	case *pb.IDV1_Bool:
		id = datalog.Bool(input.GetBool())
	case *pb.IDV1_Set:
		elts := input.GetSet().Set
		if len(elts) == 0 {
			return nil, errors.New("biscuit: failed to convert proto ID to token ID: set cannot be empty")
		}

		expectedEltType := reflect.TypeOf(elts[0].GetContent())
		switch expectedEltType {
		case reflect.TypeOf(&pb.IDV1_Variable{}):
			return nil, errors.New("biscuit: failed to convert proto ID to token ID: set cannot contains variable")
		case reflect.TypeOf(&pb.IDV1_Set{}):
			return nil, errors.New("biscuit: failed to convert proto ID to token ID: set cannot contains other sets")
		}

		datalogSet := make(datalog.Set, 0, len(elts))
		for _, protoElt := range elts {
			if eltType := reflect.TypeOf(protoElt.GetContent()); eltType != expectedEltType {
				return nil, fmt.Errorf(
					"biscuit: failed to convert proto ID to token ID: set elements must have the same type (got %x, want %x)",
					eltType,
					expectedEltType,
				)
			}

			datalogElt, err := protoIDToTokenIDV1(protoElt)
			if err != nil {
				return nil, err
			}
			datalogSet = append(datalogSet, *datalogElt)
		}
		id = datalogSet
	default:
		return nil, fmt.Errorf("biscuit: failed to convert proto ID to token ID: unsupported id type: %T", input.Content)
	}

	return &id, nil
}

func tokenRuleToProtoRuleV1(input datalog.Rule) (*pb.RuleV1, error) {
	pbBody := make([]*pb.PredicateV1, len(input.Body))
	for i, p := range input.Body {
		pred, err := tokenPredicateToProtoPredicateV1(p)
		if err != nil {
			return nil, err
		}
		pbBody[i] = pred
	}

	pbExpressions := make([]*pb.ExpressionV1, len(input.Expressions))
	for i, e := range input.Expressions {
		expr, err := tokenExpressionToProtoExpressionV1(e)
		if err != nil {
			return nil, err
		}
		pbExpressions[i] = expr
	}

	pbHead, err := tokenPredicateToProtoPredicateV1(input.Head)
	if err != nil {
		return nil, err
	}

	return &pb.RuleV1{
		Head:        pbHead,
		Body:        pbBody,
		Expressions: pbExpressions,
	}, nil
}

func protoRuleToTokenRuleV1(input *pb.RuleV1) (*datalog.Rule, error) {
	body := make([]datalog.Predicate, len(input.Body))
	for i, pb := range input.Body {
		b, err := protoPredicateToTokenPredicateV1(pb)
		if err != nil {
			return nil, err
		}
		body[i] = *b
	}

	expressions := make([]datalog.Expression, len(input.Expressions))
	for i, pbExpression := range input.Expressions {
		e, err := protoExpressionToTokenExpressionV1(pbExpression)
		if err != nil {
			return nil, err
		}
		expressions[i] = e
	}

	head, err := protoPredicateToTokenPredicateV1(input.Head)
	if err != nil {
		return nil, err
	}
	return &datalog.Rule{
		Head:        *head,
		Body:        body,
		Expressions: expressions,
	}, nil
}

func tokenExpressionToProtoExpressionV1(input datalog.Expression) (*pb.ExpressionV1, error) {
	pbExpr := &pb.ExpressionV1{
		Ops: make([]*pb.Op, len(input)),
	}

	for i, op := range input {
		switch op.Type() {
		case datalog.OpTypeValue:
			pbID, err := tokenIDToProtoIDV1(op.(datalog.Value).ID)
			if err != nil {
				return nil, err
			}
			pbExpr.Ops[i] = &pb.Op{Content: &pb.Op_Value{Value: pbID}}
		case datalog.OpTypeUnary:
			pbUnary, err := tokenExprUnaryToProtoExprUnary(op.(datalog.UnaryOp))
			if err != nil {
				return nil, err
			}
			pbExpr.Ops[i] = &pb.Op{Content: &pb.Op_Unary{Unary: pbUnary}}
		case datalog.OpTypeBinary:
			pbBinary, err := tokenExprBinaryToProtoExprBinary(op.(datalog.BinaryOp))
			if err != nil {
				return nil, err
			}
			pbExpr.Ops[i] = &pb.Op{Content: &pb.Op_Binary{Binary: pbBinary}}
		default:
			return nil, fmt.Errorf("biscuit: unsupported expression type: %v", op.Type())
		}
	}
	return pbExpr, nil
}

func protoExpressionToTokenExpressionV1(input *pb.ExpressionV1) (datalog.Expression, error) {
	expr := make(datalog.Expression, len(input.Ops))
	for i, op := range input.Ops {
		switch op.Content.(type) {
		case *pb.Op_Value:
			id, err := protoIDToTokenIDV1(op.GetValue())
			if err != nil {
				return nil, err
			}
			expr[i] = datalog.Value{ID: *id}
		case *pb.Op_Unary:
			op, err := protoExprUnaryToTokenExprUnary(op.GetUnary())
			if err != nil {
				return nil, err
			}
			expr[i] = datalog.UnaryOp{UnaryOpFunc: op}
		case *pb.Op_Binary:
			op, err := protoExprBinaryToTokenExprBinary(op.GetBinary())
			if err != nil {
				return nil, err
			}
			expr[i] = datalog.BinaryOp{BinaryOpFunc: op}
		default:
			return nil, fmt.Errorf("biscuit: unsupported proto expression type: %T", op.Content)
		}
	}
	return expr, nil
}

func tokenExprUnaryToProtoExprUnary(op datalog.UnaryOp) (*pb.OpUnary, error) {
	var pbUnaryKind pb.OpUnary_Kind
	switch op.UnaryOpFunc.Type() {
	case datalog.UnaryNegate:
		pbUnaryKind = pb.OpUnary_Negate
	case datalog.UnaryParens:
		pbUnaryKind = pb.OpUnary_Parens
	default:
		return nil, fmt.Errorf("biscuit: unsupported UnaryOpFunc type: %v", op.UnaryOpFunc.Type())
	}
	return &pb.OpUnary{Kind: pbUnaryKind}, nil
}

func protoExprUnaryToTokenExprUnary(op *pb.OpUnary) (datalog.UnaryOpFunc, error) {
	var unaryOp datalog.UnaryOpFunc
	switch op.Kind {
	case pb.OpUnary_Negate:
		unaryOp = datalog.Negate{}
	case pb.OpUnary_Parens:
		unaryOp = datalog.Parens{}
	default:
		return nil, fmt.Errorf("biscuit: unsupported proto OpUnary type: %v", op.Kind)
	}
	return unaryOp, nil
}

func tokenExprBinaryToProtoExprBinary(op datalog.BinaryOp) (*pb.OpBinary, error) {
	var pbBinaryKind pb.OpBinary_Kind
	switch op.BinaryOpFunc.Type() {
	case datalog.BinaryLessThan:
		pbBinaryKind = pb.OpBinary_LessThan
	case datalog.BinaryLessOrEqual:
		pbBinaryKind = pb.OpBinary_LessOrEqual
	case datalog.BinaryGreaterThan:
		pbBinaryKind = pb.OpBinary_GreaterThan
	case datalog.BinaryGreaterOrEqual:
		pbBinaryKind = pb.OpBinary_GreaterOrEqual
	case datalog.BinaryEqual:
		pbBinaryKind = pb.OpBinary_Equal
	case datalog.BinaryContains:
		pbBinaryKind = pb.OpBinary_Contains
	case datalog.BinaryPrefix:
		pbBinaryKind = pb.OpBinary_Prefix
	case datalog.BinarySuffix:
		pbBinaryKind = pb.OpBinary_Suffix
	case datalog.BinaryRegex:
		pbBinaryKind = pb.OpBinary_Regex
	case datalog.BinaryAdd:
		pbBinaryKind = pb.OpBinary_Add
	case datalog.BinarySub:
		pbBinaryKind = pb.OpBinary_Sub
	case datalog.BinaryMul:
		pbBinaryKind = pb.OpBinary_Mul
	case datalog.BinaryDiv:
		pbBinaryKind = pb.OpBinary_Div
	case datalog.BinaryAnd:
		pbBinaryKind = pb.OpBinary_And
	case datalog.BinaryOr:
		pbBinaryKind = pb.OpBinary_Or
	default:
		return nil, fmt.Errorf("biscuit: unsupported BinaryOpFunc type: %v", op.BinaryOpFunc.Type())
	}
	return &pb.OpBinary{Kind: pbBinaryKind}, nil
}

func protoExprBinaryToTokenExprBinary(op *pb.OpBinary) (datalog.BinaryOpFunc, error) {
	var binaryOp datalog.BinaryOpFunc
	switch op.Kind {
	case pb.OpBinary_LessThan:
		binaryOp = datalog.LessThan{}
	case pb.OpBinary_GreaterThan:
		binaryOp = datalog.GreaterThan{}
	case pb.OpBinary_LessOrEqual:
		binaryOp = datalog.LessOrEqual{}
	case pb.OpBinary_GreaterOrEqual:
		binaryOp = datalog.GreaterOrEqual{}
	case pb.OpBinary_Equal:
		binaryOp = datalog.Equal{}
	case pb.OpBinary_Contains:
		binaryOp = datalog.Contains{}
	case pb.OpBinary_Prefix:
		binaryOp = datalog.Prefix{}
	case pb.OpBinary_Suffix:
		binaryOp = datalog.Suffix{}
	case pb.OpBinary_Regex:
		binaryOp = datalog.Regex{}
	case pb.OpBinary_Add:
		binaryOp = datalog.Add{}
	case pb.OpBinary_Sub:
		binaryOp = datalog.Sub{}
	case pb.OpBinary_Mul:
		binaryOp = datalog.Mul{}
	case pb.OpBinary_Div:
		binaryOp = datalog.Div{}
	case pb.OpBinary_And:
		binaryOp = datalog.And{}
	case pb.OpBinary_Or:
		binaryOp = datalog.Or{}
	default:
		return nil, fmt.Errorf("biscuit: unsupported proto OpBinary type: %v", op.Kind)
	}
	return binaryOp, nil
}

func tokenCheckToProtoCheckV1(input datalog.Check) (*pb.CheckV1, error) {
	pbQueries := make([]*pb.RuleV1, len(input.Queries))
	for i, query := range input.Queries {
		q, err := tokenRuleToProtoRuleV1(query)
		if err != nil {
			return nil, err
		}
		pbQueries[i] = q
	}

	return &pb.CheckV1{
		Queries: pbQueries,
	}, nil
}

func protoCheckToTokenCheckV1(input *pb.CheckV1) (*datalog.Check, error) {
	queries := make([]datalog.Rule, len(input.Queries))
	for i, query := range input.Queries {
		q, err := protoRuleToTokenRuleV1(query)
		if err != nil {
			return nil, err
		}
		queries[i] = *q
	}

	return &datalog.Check{
		Queries: queries,
	}, nil
}
