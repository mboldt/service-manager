package filters

import (
	"fmt"
	"net/http"

	"github.com/Peripli/service-manager/pkg/query"

	httpsec "github.com/Peripli/service-manager/pkg/security/http"

	"github.com/Peripli/service-manager/pkg/web"
)

const OIDCLabelCriteriaFilterName = "OIDCLabelCriteriaFilter"

type OIDCLabelCriteriaFilter struct {
	LabelCriteriaKeysGroupedByClaims map[string]string
}

func (f *OIDCLabelCriteriaFilter) Name() string {
	return OIDCLabelCriteriaFilterName
}

func (f *OIDCLabelCriteriaFilter) Run(request *web.Request, next web.Handler) (*web.Response, error) {
	ctx := request.Context()
	//TODO logging
	//logger := log.C(ctx)

	user, ok := web.UserFromContext(ctx)
	if !ok {
		return next.Handle(request)
	}

	tokenData, isTokenData := user.Data.(httpsec.TokenData)
	if !isTokenData {
		return next.Handle(request)
	}

	var claims map[string]string
	if err := tokenData.Claims(&claims); err != nil {
		return nil, fmt.Errorf("could not find ZID in token claims: %s", err)
	}

	for claimKey := range f.LabelCriteriaKeysGroupedByClaims {
		criterion := query.ByLabel(query.EqualsOperator, f.LabelCriteriaKeysGroupedByClaims[claimKey], claims[claimKey])
		var err error
		ctx, err = query.AddCriteria(ctx, criterion)
		if err != nil {
			return nil, fmt.Errorf("could not add label critaria with key %s and value %s: %s", f.LabelCriteriaKeysGroupedByClaims[claimKey], claims[claimKey], err)
		}
	}
	request.Request = request.WithContext(ctx)

	return next.Handle(request)
}

func (*OIDCLabelCriteriaFilter) FilterMatchers() []web.FilterMatcher {
	return []web.FilterMatcher{
		{
			Matchers: []web.Matcher{
				//TODO delete by label query
				// option 1 - we already do list before delete so we can just change the repository interface  to delete objects instead of delete by criteria
				// option 2 - extend querybuilder
				web.Methods(http.MethodGet, http.MethodPatch),
			},
		},
	}
}
