package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/prometheus/prometheus/model/labels"

	"github.com/observatorium/api/authorization"
	"github.com/observatorium/api/httperr"
	logqlv2 "github.com/observatorium/api/logql/v2"
)

type AuthzResponseData struct {
	Matchers  []*labels.Matcher `json:"matchers,omitempty"`
	MatcherOp string            `json:"matcherOp,omitempty"`
}

const (
	logicalOr  = "or"
	queryParam = "query"
	matchParam = "match"
)

type matchersContextKey struct{}

// WithEnforceAuthorizationLabels return a middleware that ensures every query
// has a set of labels returned by the OPA authorizer enforced.
func WithEnforceAuthorizationLabels() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data, ok := authorization.GetData(r.Context())
			if !ok {
				httperr.PrometheusAPIError(w, "error finding authorization label matcher", http.StatusInternalServerError)

				return
			}

			// Early pass to the next if no authz
			// label enforcement configured.
			if data == "" {
				next.ServeHTTP(w, r)

				return
			}
			if strings.Contains(r.URL.Path, "/loki/api/") || strings.Contains(r.URL.Path, "/api/prom/") {
				// Label-scoped reads must not forward an unenforced POST body or
				// a new Loki endpoint whose selectors have not been audited.
				if r.Method != http.MethodGet {
					httperr.PrometheusAPIError(w, "label-scoped reads require GET", http.StatusMethodNotAllowed)
					return
				}
				path := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
				switch path {
				case "query", "query_range", "labels", "label", "values", "series", "tail":
				default:
					httperr.PrometheusAPIError(w, "endpoint does not support label-scoped reads", http.StatusForbidden)
					return
				}
			}

			var matchersInfo AuthzResponseData
			if err := json.Unmarshal([]byte(data), &matchersInfo); err != nil {
				httperr.PrometheusAPIError(w, "error parsing authorization label matchers", http.StatusInternalServerError)

				return
			}
			r = r.WithContext(context.WithValue(r.Context(), matchersContextKey{}, matchersInfo))

			q, err := enforceValues(matchersInfo, r.URL)
			if err != nil {
				httperr.PrometheusAPIError(w, fmt.Sprintf("could not enforce authorization label matchers: %v", err), http.StatusInternalServerError)

				return
			}
			r.URL.RawQuery = q

			next.ServeHTTP(w, r)
		})
	}
}

func enforceValues(mInfo AuthzResponseData, u *url.URL) (values string, err error) {
	switch {
	case strings.HasSuffix(u.Path, "/values"), strings.HasSuffix(u.Path, "/labels"), strings.HasSuffix(u.Path, "/label"):
		return enforceValuesOnLogQL(mInfo, u.Query(), queryParam, false)
	case strings.HasSuffix(u.Path, "/series"):
		v := u.Query()
		param := "match[]"
		if _, ok := v[param]; !ok {
			param = matchParam
		}
		return enforceAllValuesOnLogQL(mInfo, v, param, false)
	default:
		return enforceValuesOnLogQL(mInfo, u.Query(), queryParam, true)
	}
}

func enforceAllValuesOnLogQL(mInfo AuthzResponseData, v url.Values, param string, queryEndpoint bool) (string, error) {
	inputs := v[param]
	if len(inputs) == 0 {
		return enforceValuesOnLogQL(mInfo, v, param, queryEndpoint)
	}
	outputs := make([]string, 0, len(inputs))
	for _, value := range inputs {
		encoded, err := enforceValuesOnLogQL(mInfo, url.Values{param: {value}}, param, queryEndpoint)
		if err != nil {
			return "", err
		}
		parsed, err := url.ParseQuery(encoded)
		if err != nil {
			return "", err
		}
		outputs = append(outputs, parsed.Get(param))
	}
	v[param] = outputs
	return v.Encode(), nil
}

func enforceValuesOnLogQL(mInfo AuthzResponseData, v url.Values, paramName string, queryEndpoint bool) (values string, err error) {
	lm, err := initAuthzMatchers(mInfo.Matchers)
	if err != nil {
		return "", err
	}

	paramValue := v.Get(paramName)
	if paramValue == "" {
		// For query endpoints, we don't always to enforce the authorization
		// label matchers, so we skip it if the query is empty.
		if queryEndpoint {
			return v.Encode(), nil
		}

		// For the other endpoints we want to enforce the authZ label matchers
		expr := &logqlv2.StreamMatcherExpr{}
		expr.SetMatchers(lm)
		v.Set(paramName, expr.String())
		return v.Encode(), nil
	}

	expr, err := logqlv2.ParseExpr(paramValue)
	if err != nil {
		return "", fmt.Errorf("failed parsing LogQL expression: %w", err)
	}

	// Logical "OR" only applies to query expressions, not for filter params
	if mInfo.MatcherOp == logicalOr && paramName == queryParam {
		// Logical "OR" to combine multiple matchers needs to be done via LogQueryExpr > LogPipelineExpr
		expr.Walk(func(expr interface{}) {
			if le, ok := expr.(*logqlv2.LogQueryExpr); ok {
				le.AppendPipelineMatchers(mInfo.Matchers, logicalOr)
			}
		})
		v.Set(paramName, expr.String())
		return v.Encode(), nil
	}

	expr.Walk(func(expr interface{}) {
		switch le := expr.(type) {
		case *logqlv2.LogQueryExpr:
			matchers := combineLabelMatchers(le.Matchers(), lm)
			le.SetMatchers(matchers)
		case *logqlv2.StreamMatcherExpr:
			matchers := combineLabelMatchers(le.Matchers(), lm)
			le.SetMatchers(matchers)
		}
	})

	v.Set(paramName, expr.String())
	return v.Encode(), nil
}

// Combine the query label matcher and the authorization label matcher.
func combineLabelMatchers(queryMatchers, authzMatchers []*labels.Matcher) []*labels.Matcher {
	matchers := append([]*labels.Matcher(nil), queryMatchers...)
	for _, am := range authzMatchers {
		implied := false
		for _, qm := range queryMatchers {
			if qm.Name == am.Name && ((qm.Type == labels.MatchEqual && am.Matches(qm.Value)) || (qm.Type == am.Type && qm.Value == am.Value)) {
				implied = true
				break
			}
		}
		if !implied {
			// Repeated label matchers are conjunctive. Preserve the caller's
			// restriction instead of replacing it with a broader one.
			matchers = append(matchers, am)
		}
	}

	return matchers
}

func initAuthzMatchers(lm []*labels.Matcher) ([]*labels.Matcher, error) {
	// Fix label matchers to include a non nil FastRegexMatcher for regex types.
	for i, m := range lm {
		nm, err := labels.NewMatcher(m.Type, m.Name, m.Value)
		if err != nil {
			return nil, fmt.Errorf("failed parsing label matcher: %w", err)
		}

		lm[i] = nm
	}

	return lm, nil
}

// AllowedNamespaces returns the list of namespaces that the user is allowed to list.
func AllowedNamespaces(ctx context.Context) []string {
	matchers := ctx.Value(matchersContextKey{})
	if matchers == nil {
		return nil
	}
	matchersTyped := matchers.(AuthzResponseData)

	var namespaces []string
	for _, m := range matchersTyped.Matchers {
		namespaces = append(namespaces, strings.Split(m.Value, "|")...)
	}
	return namespaces
}
