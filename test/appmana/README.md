# AppMana Resource Authorization Acceptance

From the repository root, build the real gateway then run the integration test:

```sh
go build -o build/observatorium-api .
APPMANA_LOG_POLICY_DIR=../../../appmana-cluster/src/charts/loki-authorization-gateway/files go test -tags=integration ./test/appmana -v -count=1
go test ./api/logs/v1 ./authentication
```

The policy path is resolved from the Go test package's working directory. Point
it at the Helm chart's `files` directory when running outside the monorepo. The
policy is not duplicated in this fork. Docker images are OPA 1.8.0-static and
Loki 3.5.3. Tests create and remove their own Docker containers and gateway
process, and never connect to a live Loki or Keycloak server.

The test uses actual HTTP requests through the gateway executable, real OPA
decisions and real Loki storage. Its local OIDC issuer serves discovery/JWKS and
signs RSA tokens. This tests issuer, audience, expiry and subject verification;
it does not claim to test Keycloak token exchange or Kubernetes CR replication.
Fixtures have WorkspaceClaim and WorkspaceMember shapes used by kube-mgmt.

Authorization is tested for namespace-scoped logs, metadata and WebSocket tails,
unrelated users, revoked membership, tenant header spoofing, unknown tenants,
and POST-body bypass. AppMana's gateway config has no write/rules upstream.

## Fork Changes

- Append mandatory matchers conjunctively without replacing caller constraints.
  Preserve negative and repeated matchers; compare semantic outcomes in tests.
- Enforce label-list queries even when the browser supplies no selector.
- Intersect each repeated series `match[]` selector.
- For label-restricted log reads, reject non-GET requests and endpoints without
  audited selector support. This avoids forwarding unenforced request bodies.
- Return 401 / Unauthenticated for invalid verified OIDC tokens rather than 500.

Source-level regressions were reproduced before fixes. The integration test also
reproduced an actual POST /series body bypass returning unauthorized namespace
metadata before the GET-only guard was added. One older enforcer assertion was
updated because replacing an inaccessible requested selector with an accessible
one broadened the query; the corrected behavior retains both constraints.

Remaining acceptance before exposure: verify kube-mgmt replication against the
actual CRDs, Keycloak audience issuance, network isolation of raw Loki, and the
bounded lifetime/revocation behavior of already-open tails.
