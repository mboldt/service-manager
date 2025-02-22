/*
 * Copyright 2018 The Service Manager Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package query

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Peripli/service-manager/pkg/util"
)

// Operator is a query operator
type Operator string

const (
	// EqualsOperator takes two operands and tests if they are equal
	EqualsOperator Operator = "="
	// NotEqualsOperator takes two operands and tests if they are not equal
	NotEqualsOperator Operator = "!="
	// GreaterThanOperator takes two operands and tests if the left is greater than the right
	GreaterThanOperator Operator = "gt"
	// GreaterThanOrEqualOperator takes two operands and tests if the left is greater than or equal the right
	GreaterThanOrEqualOperator Operator = "gte"
	// LessThanOperator takes two operands and tests if the left is lesser than the right
	LessThanOperator Operator = "lt"
	// LessThanOrEqualOperator takes two operands and tests if the left is lesser than or equal the right
	LessThanOrEqualOperator Operator = "lte"
	// InOperator takes two operands and tests if the left is contained in the right
	InOperator Operator = "in"
	// NotInOperator takes two operands and tests if the left is not contained in the right
	NotInOperator Operator = "notin"
	// EqualsOrNilOperator takes two operands and tests if the left is equal to the right, or if the left is nil
	EqualsOrNilOperator Operator = "eqornil"
	// NoOperator signifies that this is not an operator
	NoOperator Operator = "nop"
)

// IsMultiVariate returns true if the operator requires right operand with multiple values
func (op Operator) IsMultiVariate() bool {
	return op == InOperator || op == NotInOperator
}

// IsNullable returns true if the operator can check if the left operand is nil
func (op Operator) IsNullable() bool {
	return op == EqualsOrNilOperator
}

// IsNumeric returns true if the operator works only with numeric operands
func (op Operator) IsNumeric() bool {
	return op == LessThanOperator || op == GreaterThanOperator || op == LessThanOrEqualOperator || op == GreaterThanOrEqualOperator
}

var operators = []Operator{EqualsOperator, NotEqualsOperator, InOperator,
	NotInOperator, GreaterThanOperator, GreaterThanOrEqualOperator, LessThanOperator, LessThanOrEqualOperator, EqualsOrNilOperator}

const (
	// OpenBracket is the token that denotes the beginning of a multivariate operand
	OpenBracket rune = '['
	// CloseBracket is the token that denotes the end of a multivariate operand
	CloseBracket rune = ']'
	// Separator is the separator between field and label queries
	Separator rune = '|'
	// OperandSeparator is the separator between the operator and the operands
	OperandSeparator rune = ' '
)

// CriterionType is a type of criteria to be applied when querying
type CriterionType string

const (
	// FieldQuery denotes that the query should be executed on the entity's fields
	FieldQuery CriterionType = "fieldQuery"
	// LabelQuery denotes that the query should be executed on the entity's labels
	LabelQuery CriterionType = "labelQuery"
	// ResultQuery is used to further process result
	ResultQuery CriterionType = "resultQuery"
)

const (
	// OrderBy should be used as a left operand in Criterion
	OrderBy string = "orderBy"
	// Limit should be used as a left operand in Criterion to signify the
	Limit string = "limit"
)

// OrderType is the type of the order in which result is presented
type OrderType string

const (
	// AscOrder orders result in ascending order
	AscOrder OrderType = "asc"
	// DescOrder orders result in descending order
	DescOrder OrderType = "desc"
)

var supportedQueryTypes = []CriterionType{FieldQuery, LabelQuery}

// Criterion is a single part of a query criteria
type Criterion struct {
	// LeftOp is the left operand in the query
	LeftOp string
	// Operator is the query operator
	Operator Operator
	// RightOp is the right operand in the query which can be multivariate
	RightOp []string
	// Type is the type of the query
	Type CriterionType
}

// ByField constructs a new criterion for field querying
func ByField(operator Operator, leftOp string, rightOp ...string) Criterion {
	return newCriterion(leftOp, operator, rightOp, FieldQuery)
}

// ByLabel constructs a new criterion for label querying
func ByLabel(operator Operator, leftOp string, rightOp ...string) Criterion {
	return newCriterion(leftOp, operator, rightOp, LabelQuery)
}

// OrderResultBy constructs a new criterion for result order
func OrderResultBy(field string, orderType OrderType) Criterion {
	return newCriterion(OrderBy, NoOperator, []string{field, string(orderType)}, ResultQuery)
}

// LimitResultBy constructs a new criterion for limit result with
func LimitResultBy(limit int) Criterion {
	limitString := strconv.Itoa(limit)
	return newCriterion(Limit, NoOperator, []string{limitString}, ResultQuery)
}

func newCriterion(leftOp string, operator Operator, rightOp []string, criteriaType CriterionType) Criterion {
	return Criterion{LeftOp: leftOp, Operator: operator, RightOp: rightOp, Type: criteriaType}
}

// Validate the criterion fields
func (c Criterion) Validate() error {
	if c.Type == ResultQuery {
		if c.LeftOp == Limit {
			limit, err := strconv.Atoi(c.RightOp[0])
			if err != nil {
				return fmt.Errorf("could not cast string to int: %s", err.Error())
			}
			if limit < 1 {
				return &util.UnsupportedQueryError{Message: fmt.Sprintf("limit (%d) is invalid. Limit should be positive number", limit)}
			}
		}

		if c.LeftOp == OrderBy {
			if len(c.RightOp) < 1 {
				return &util.UnsupportedQueryError{Message: "order by result expects field and order type, but has none"}
			}
			if len(c.RightOp) < 2 {
				return &util.UnsupportedQueryError{Message: fmt.Sprintf(`order by result for field "%s" expects order type, but has none`, c.RightOp[0])}
			}
		}

		return nil
	}

	if len(c.RightOp) > 1 && !c.Operator.IsMultiVariate() {
		return &util.UnsupportedQueryError{Message: fmt.Sprintf("multiple values %s received for single value operation %s", c.RightOp, c.Operator)}
	}
	if c.Operator.IsNullable() && c.Type != FieldQuery {
		return &util.UnsupportedQueryError{Message: "nullable operations are supported only for field queries"}
	}
	if c.Operator.IsNumeric() && !isNumeric(c.RightOp[0]) && !isDateTime(c.RightOp[0]) {
		return &util.UnsupportedQueryError{Message: fmt.Sprintf("%s is numeric operator, but the right operand %s is not numeric or datetime", c.Operator, c.RightOp[0])}
	}

	if strings.ContainsRune(c.LeftOp, Separator) {
		parts := strings.FieldsFunc(c.LeftOp, func(r rune) bool {
			return r == Separator
		})
		possibleKey := parts[len(parts)-1]
		return &util.UnsupportedQueryError{Message: fmt.Sprintf("separator %c is not allowed in %s with left operand \"%s\". Maybe you meant \"%s\"? Make sure if the separator is present in any right operand, that it is escaped with a backslash (\\)", Separator, c.Type, c.LeftOp, possibleKey)}
	}
	for _, op := range c.RightOp {
		if strings.ContainsRune(op, '\n') {
			return &util.UnsupportedQueryError{Message: fmt.Sprintf("%s with key \"%s\" has value \"%s\" contaning forbidden new line character", c.Type, c.LeftOp, op)}
		}
	}
	return nil
}

func mergeCriteria(c1 []Criterion, c2 []Criterion) ([]Criterion, error) {
	result := c1
	fieldQueryLeftOperands := make(map[string]int)
	labelQueryLeftOperands := make(map[string]int)

	for _, criterion := range append(c1, c2...) {
		if criterion.Type == FieldQuery {
			fieldQueryLeftOperands[criterion.LeftOp]++
		}
		if criterion.Type == LabelQuery {
			labelQueryLeftOperands[criterion.LeftOp]++
		}
	}

	for _, newCriterion := range c2 {
		leftOp := newCriterion.LeftOp
		// disallow duplicate label queries
		if count, ok := labelQueryLeftOperands[leftOp]; ok && count > 1 && newCriterion.Type == LabelQuery {
			return nil, &util.UnsupportedQueryError{Message: fmt.Sprintf("duplicate label query key: %s", newCriterion.LeftOp)}
		}
		// disallow duplicate field query keys
		if count, ok := fieldQueryLeftOperands[leftOp]; ok && count > 1 && newCriterion.Type == FieldQuery {
			return nil, &util.UnsupportedQueryError{Message: fmt.Sprintf("duplicate field query key: %s", newCriterion.LeftOp)}
		}
		if err := newCriterion.Validate(); err != nil {
			return nil, err
		}
	}
	result = append(result, c2...)
	return result, nil
}

type criteriaCtxKey struct{}

// AddCriteria adds the given criteria to the context and returns an error if any of the criteria is not valid
func AddCriteria(ctx context.Context, newCriteria ...Criterion) (context.Context, error) {
	currentCriteria := CriteriaForContext(ctx)
	criteria, err := mergeCriteria(currentCriteria, newCriteria)
	if err != nil {
		return nil, err
	}
	return context.WithValue(ctx, criteriaCtxKey{}, criteria), nil
}

// CriteriaForContext returns the criteria for the given context
func CriteriaForContext(ctx context.Context) []Criterion {
	currentCriteria := ctx.Value(criteriaCtxKey{})
	if currentCriteria == nil {
		return []Criterion{}
	}
	return currentCriteria.([]Criterion)
}

// ContextWithCriteria returns a new context with given criteria
func ContextWithCriteria(ctx context.Context, criteria []Criterion) context.Context {
	return context.WithValue(ctx, criteriaCtxKey{}, criteria)
}

// BuildCriteriaFromRequest builds criteria for the given request's query params and returns an error if the query is not valid
func BuildCriteriaFromRequest(request *http.Request) ([]Criterion, error) {
	var criteria []Criterion
	for _, queryType := range supportedQueryTypes {
		queryValues := request.URL.Query().Get(string(queryType))
		querySegments, err := process(queryValues, queryType)
		if err != nil {
			return nil, err
		}
		if criteria, err = mergeCriteria(criteria, querySegments); err != nil {
			return nil, err
		}
	}
	sort.Sort(ByLeftOp(criteria))
	return criteria, nil
}

type ByLeftOp []Criterion

func (c ByLeftOp) Len() int {
	return len(c)
}

func (c ByLeftOp) Less(i, j int) bool {
	return c[i].LeftOp < c[j].LeftOp
}

func (c ByLeftOp) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}

func process(input string, criteriaType CriterionType) ([]Criterion, error) {
	var c []Criterion
	if input == "" {
		return c, nil
	}
	var leftOp string
	var operator Operator
	j := 0
	for i := 0; i < len(input); i++ {
		if leftOp != "" && operator != "" {
			remaining := input[i+len(operator)+1:]
			rightOp, offset, err := findRightOp(remaining, leftOp, operator, criteriaType)
			if err != nil {
				return nil, err
			}
			criterion := newCriterion(leftOp, operator, rightOp, criteriaType)
			if err := criterion.Validate(); err != nil {
				return nil, err
			}
			c = append(c, criterion)
			i += offset + len(operator) + len(string(Separator))
			j = i + 1
			leftOp = ""
			operator = ""
		} else {
			remaining := input[i:]
			for _, op := range operators {
				if strings.HasPrefix(remaining, fmt.Sprintf("%c%s%c", OperandSeparator, op, OperandSeparator)) {
					leftOp = input[j:i]
					operator = op
					break
				}
			}
		}
	}
	if len(c) == 0 {
		return nil, &util.UnsupportedQueryError{
			Message: fmt.Sprintf("%s is not a valid %s", input, criteriaType),
		}
	}
	return c, nil
}

func findRightOp(remaining string, leftOp string, operator Operator, criteriaType CriterionType) (rightOp []string, offset int, err error) {
	rightOpBuffer := strings.Builder{}
	for _, ch := range remaining {
		if ch == Separator {
			if offset+1 < len(remaining) && rune(remaining[offset+1]) == Separator && remaining[offset-1] != '\\' {
				arg := rightOpBuffer.String()
				rightOp = append(rightOp, arg)
				rightOpBuffer.Reset()
			} else if rune(remaining[offset-1]) == Separator {
				offset++
				continue
			} else {
				if remaining[offset-1] != '\\' { // delimiter is not escaped - treat as separator
					arg := rightOpBuffer.String()
					rightOp = append(rightOp, arg)
					rightOpBuffer.Reset()
					break
				} else { // remove escaping symbol
					tmp := rightOpBuffer.String()[:offset-1]
					rightOpBuffer.Reset()
					rightOpBuffer.WriteString(tmp)
					rightOpBuffer.WriteRune(ch)
				}
			}
		} else {
			rightOpBuffer.WriteRune(ch)
		}
		offset++
	}
	if rightOpBuffer.Len() > 0 {
		rightOp = append(rightOp, rightOpBuffer.String())
	}
	if len(rightOp) > 0 && operator.IsMultiVariate() {
		firstElement := rightOp[0]
		if strings.IndexRune(firstElement, OpenBracket) == 0 {
			rightOp[0] = firstElement[1:]
		} else {
			return nil, -1, &util.UnsupportedQueryError{Message: fmt.Sprintf("operator %s for %s %s requires right operand to be surrounded in %c%c", operator, criteriaType, leftOp, OpenBracket, CloseBracket)}
		}
		lastElement := rightOp[len(rightOp)-1]
		if rune(lastElement[len(lastElement)-1]) == CloseBracket {
			rightOp[len(rightOp)-1] = lastElement[:len(lastElement)-1]
		} else {
			return nil, -1, &util.UnsupportedQueryError{Message: fmt.Sprintf("operator %s for %s %s requires right operand to be surrounded in %c%c", operator, criteriaType, leftOp, OpenBracket, CloseBracket)}
		}
	}
	if len(rightOp) == 0 {
		rightOp = append(rightOp, "")
	}
	return
}

func isNumeric(str string) bool {
	_, err := strconv.Atoi(str)
	if err == nil {
		return true
	}
	_, err = strconv.ParseFloat(str, 64)
	return err == nil
}

func isDateTime(str string) bool {
	_, err := time.Parse(time.RFC3339, str)
	return err == nil
}
