/*
 * Copyright 2018 The Service Manager Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/Peripli/service-manager/pkg/query"

	. "github.com/Peripli/service-manager/storage/postgres/postgresfakes"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Postgres Storage Abstract", func() {

	var ctx context.Context
	var baseTable string
	var labelsTable string
	var executedQuery string
	var queryArgs []interface{}

	db := &FakePgDB{}
	db.QueryxContextStub = func(ctx context.Context, query string, args ...interface{}) (rows *sqlx.Rows, e error) {
		executedQuery = query
		queryArgs = args
		return &sqlx.Rows{}, nil
	}
	db.SelectContextStub = func(ctx context.Context, dest interface{}, query string, args ...interface{}) error {
		executedQuery = query
		queryArgs = args
		return nil
	}
	db.ExecContextStub = func(ctx context.Context, query string, args ...interface{}) (result sql.Result, e error) {
		executedQuery = query
		queryArgs = args
		return driver.RowsAffected(1), nil
	}
	db.RebindStub = func(s string) string {
		return s
	}

	BeforeEach(func() {
		ctx = context.TODO()
		executedQuery = ""
		baseTable = "table_name"
		labelsTable = "labels_table_name"
		queryArgs = []interface{}{}
	})

	Describe("updateQuery", func() {

		Context("Called with structure with no db tag", func() {
			It("Should return proper query", func() {
				type ts struct {
					Field string
				}
				query := updateQuery("n/a", ts{Field: "value"})
				Expect(query).To(Equal("UPDATE n/a SET field = :field WHERE id = :id"))
			})
		})

		Context("Called with structure with db tag", func() {
			It("Should return proper query", func() {
				type ts struct {
					Field string `db:"taggedField"`
				}
				query := updateQuery("n/a", ts{Field: "value"})
				Expect(query).To(Equal("UPDATE n/a SET taggedField = :taggedField WHERE id = :id"))
			})
		})

		Context("Called with structure with empty field", func() {
			It("allows setting default values for fields", func() {
				type ts struct {
					Field string
				}
				query := updateQuery("n/a", ts{})
				Expect(query).To(Equal("UPDATE n/a SET field = :field WHERE id = :id"))
			})
		})

		Context("Called with structure with nil field", func() {
			It("ignores nils", func() {
				type ts struct {
					Field *string
				}
				query := updateQuery("n/a", ts{})
				Expect(query).To(Equal(""))
			})
		})

		Context("Called with structure with no fields", func() {
			It("Should return proper query", func() {
				type ts struct{}
				query := updateQuery("n/a", ts{})
				Expect(query).To(Equal(""))
			})
		})
	})

	Describe("List with labels and criteria", func() {
		Context("When criteria uses a missing entity field", func() {
			It("Should return an error", func() {
				invalidCriterion := []query.Criterion{query.ByField(query.EqualsOperator, "non-existing-field", "value")}
				rows, err := listWithLabelsAndCriteria(ctx, db, Visibility{}, &VisibilityLabel{}, baseTable, labelsTable, invalidCriterion)
				Expect(rows).To(BeNil())
				Expect(err).To(HaveOccurred())
			})
		})

		Context("When querying with equals or nil field query", func() {
			It("Should construct correct SQL query", func() {
				fieldName := "platform_id"
				queryValue := "value"
				expectedQuery := fmt.Sprintf(`SELECT %[1]s.*, %[2]s.id "%[2]s.id", %[2]s.key "%[2]s.key", %[2]s.val "%[2]s.val", %[2]s.created_at "%[2]s.created_at", %[2]s.updated_at "%[2]s.updated_at", %[2]s.visibility_id "%[2]s.visibility_id" FROM %[1]s LEFT JOIN %[2]s ON %[1]s.id = %[2]s.visibility_id WHERE (%[1]s.%[3]s = ? OR %[1]s.%[3]s IS NULL);`, baseTable, labelsTable, fieldName)

				invalidCriterion := []query.Criterion{query.ByField(query.EqualsOrNilOperator, fieldName, queryValue)}
				rows, err := listWithLabelsAndCriteria(ctx, db, Visibility{}, &VisibilityLabel{}, baseTable, labelsTable, invalidCriterion)
				Expect(rows).ToNot(BeNil())
				Expect(err).ToNot(HaveOccurred())
				Expect(executedQuery).To(Equal(expectedQuery))
				Expect(queryArgs).To(ConsistOf(queryValue))
			})
		})

		Context("When querying with field and label query", func() {
			It("Should construct correct SQL query", func() {
				fieldName := "platform_id"
				queryValue := "value"
				labelKey := "label_key"
				labelValue := "labelValue"
				expectedQuery := fmt.Sprintf(`SELECT %[1]s.*, %[2]s.id "%[2]s.id", %[2]s.key "%[2]s.key", %[2]s.val "%[2]s.val", %[2]s.created_at "%[2]s.created_at", %[2]s.updated_at "%[2]s.updated_at", %[2]s.visibility_id "%[2]s.visibility_id" FROM %[1]s LEFT JOIN %[2]s ON %[1]s.id = %[2]s.visibility_id WHERE %[1]s.%[3]s = ? AND %[2]s.key = ? AND %[2]s.val = ?;`, baseTable, labelsTable, fieldName)

				criteria := []query.Criterion{
					query.ByField(query.EqualsOperator, fieldName, queryValue),
					query.ByLabel(query.EqualsOperator, labelKey, labelValue),
				}

				rows, err := listWithLabelsAndCriteria(ctx, db, Visibility{}, &VisibilityLabel{}, baseTable, labelsTable, criteria)
				Expect(rows).ToNot(BeNil())
				Expect(err).ToNot(HaveOccurred())
				Expect(executedQuery).To(Equal(expectedQuery))
				Expect(queryArgs).To(ConsistOf(queryValue, labelKey, labelValue))
			})
		})
	})
	Describe("List by field criteria", func() {
		Context("When passing no criteria", func() {
			It("Should construct base SQL query", func() {
				err := listByFieldCriteria(ctx, db, baseTable, Visibility{})
				Expect(err).ToNot(HaveOccurred())
				Expect(executedQuery).To(Equal(fmt.Sprintf("SELECT * FROM %s;", baseTable)))
			})
		})
		Context("When passing correct criteria", func() {
			It("Should construct correct SQL query", func() {
				fieldName := "platform_id"
				queryValue := "value"
				expectedQuery := fmt.Sprintf(`SELECT * FROM %[1]s WHERE %[1]s.%[2]s = ?;`, baseTable, fieldName)

				criteria := []query.Criterion{
					query.ByField(query.EqualsOperator, fieldName, queryValue),
				}

				err := listByFieldCriteria(ctx, db, baseTable, Visibility{}, criteria...)
				Expect(err).ToNot(HaveOccurred())
				Expect(executedQuery).To(Equal(expectedQuery))
				Expect(queryArgs).To(ConsistOf(queryValue))
			})
		})
	})

	Describe("Delete all by criteria", func() {

		Context("When deleting by label", func() {
			It("Should return an error", func() {
				err := deleteAllByFieldCriteria(ctx, db, baseTable, Visibility{}, query.ByLabel(query.EqualsOperator, "left", "right"))
				Expect(err).To(HaveOccurred())
			})
		})

		Context("When no criteria is passed", func() {
			It("Should construct query to delete all entries", func() {
				expectedQuery := fmt.Sprintf("DELETE FROM %s;", baseTable)
				err := deleteAllByFieldCriteria(ctx, db, baseTable, Visibility{})
				Expect(err).ToNot(HaveOccurred())
				Expect(executedQuery).To(Equal(expectedQuery))
			})
		})

		Context("When criteria uses missing field", func() {
			It("Should return error", func() {
				err := deleteAllByFieldCriteria(ctx, db, baseTable, Visibility{}, query.ByField(query.EqualsOperator, "non-existing-field", "value"))
				Expect(err).To(HaveOccurred())
			})
		})
	})
})
