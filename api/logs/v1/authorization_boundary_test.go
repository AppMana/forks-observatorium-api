package http

import (
	"net/url"
	"testing"

	"github.com/prometheus/prometheus/model/labels"
)

func TestAuthorizationMatchersNeverPermitDeniedNamespaces(t *testing.T) {
	authorized := labels.MustNewMatcher(labels.MatchEqual, "namespace", "allowed")
	for _, kind := range []labels.MatchType{labels.MatchNotEqual, labels.MatchNotRegexp} {
		t.Run(kind.String(), func(t *testing.T) {
			requested := labels.MustNewMatcher(kind, "namespace", "allowed")
			combined := combineLabelMatchers([]*labels.Matcher{requested}, []*labels.Matcher{authorized})
			for _, value := range []string{"allowed", "other", ""} {
				matches := true
				for _, matcher := range combined {
					matches = matches && matcher.Matches(value)
				}
				if matches != (requested.Matches(value) && authorized.Matches(value)) {
					t.Fatalf("authorization did not intersect %s with %s for namespace %q: %v", requested, authorized, value, combined)
				}
			}
		})
	}
}

func TestAuthorizationFiltersLabelsWithoutQuery(t *testing.T) {
	u, _ := url.Parse("/loki/api/v1/labels")
	result, err := enforceValues(AuthzResponseData{Matchers: []*labels.Matcher{
		labels.MustNewMatcher(labels.MatchEqual, "namespace", "allowed"),
	}}, u)
	if err != nil {
		t.Fatal(err)
	}
	values, _ := url.ParseQuery(result)
	if values.Get("query") != `{namespace="allowed"}` {
		t.Fatalf("unscoped labels request: %s", result)
	}
}

func TestAuthorizationIntersectsEverySeriesSelector(t *testing.T) {
	u, _ := url.Parse(`/loki/api/v1/series?match%5B%5D=%7Bnamespace%3D%22allowed%22%7D&match%5B%5D=%7Bnamespace%3D%22other%22%7D`)
	result, err := enforceValues(AuthzResponseData{Matchers: []*labels.Matcher{
		labels.MustNewMatcher(labels.MatchEqual, "namespace", "allowed"),
	}}, u)
	if err != nil {
		t.Fatal(err)
	}
	values, _ := url.ParseQuery(result)
	selectors := values["match[]"]
	if len(selectors) != 2 || selectors[1] != `{namespace="other", namespace="allowed"}` {
		t.Fatalf("series selectors not intersected: %s", result)
	}
}
