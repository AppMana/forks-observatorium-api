//go:build integration

package appmana_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/websocket"
)

// This starts the real gateway executable, OPA and Loki. The local OIDC fixture
// issues signed tokens through real discovery/JWKS verification, not auth mocks.
func TestWorkspaceLogAuthorization(t *testing.T) {
	policyDir := os.Getenv("APPMANA_LOG_POLICY_DIR")
	if policyDir == "" {
		t.Fatal("set APPMANA_LOG_POLICY_DIR to the checked-in cluster policies/loki directory")
	}
	policyDir, err := filepath.Abs(policyDir)
	must(t, err)
	binary, err := filepath.Abs("../../build/observatorium-api")
	must(t, err)
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(t, err)
	var issuer *httptest.Server
	issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/keys" {
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "test", "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB"}}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"issuer": issuer.URL, "jwks_uri": issuer.URL + "/keys", "authorization_endpoint": issuer.URL + "/authorize", "token_endpoint": issuer.URL + "/token", "id_token_signing_alg_values_supported": []string{"RS256"}})
	}))
	t.Cleanup(issuer.Close)
	token := func(subject, audience, iss string, expires time.Time, groups ...string) string {
		v := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": subject, "aud": audience, "iss": iss, "exp": expires.Unix(), "iat": time.Now().Add(-time.Minute).Unix(), "groups": groups})
		v.Header["kid"] = "test"
		signed, err := v.SignedString(key)
		must(t, err)
		return signed
	}
	claims := map[string]any{"metadata": map[string]any{"name": "workspace", "generation": 1}, "status": map[string]any{"phase": "Ready", "observedGeneration": 1, "namespaces": map[string]string{"control": "owner-control", "build": "owner-build", "runtime": "owner-runtime"}}}
	member := map[string]any{"metadata": map[string]any{"name": "owner"}, "spec": map[string]string{"principal": issuer.URL + "#owner", "accessRole": "admin"}}
	data := map[string]any{"appmana_log_settings": map[string]string{"issuer": issuer.URL}, "kubernetes": map[string]any{"workspaceclaims": map[string]any{"claims": map[string]any{"workspace": claims}}, "workspacemembers": map[string]any{"owner-control": map[string]any{"owner": member}}}}
	encoded, err := json.Marshal(data)
	must(t, err)
	must(t, os.WriteFile(filepath.Join(dir, "data.json"), encoded, 0644))
	opaPort, lokiPort, gatewayPort, internalPort := port(t), port(t), port(t), port(t)
	opa := fmt.Sprintf("http://127.0.0.1:%d", opaPort)
	loki := fmt.Sprintf("http://127.0.0.1:%d", lokiPort)
	docker(t, "opa", "-v", policyDir+":/policy:ro", "-v", dir+":/fixtures:ro", "openpolicyagent/opa:1.21.4-static@sha256:47f93480b09e24c220ae75f1e9133585ba6d698059951668d35e6a4fc32ebc82", "run", "--server", fmt.Sprintf("--addr=127.0.0.1:%d", opaPort), "/policy/workspace.rego", "/fixtures/data.json")
	// Keep fixture storage isolated from host disk-utilization thresholds.
	docker(t, "loki", "--tmpfs", "/loki:rw,size=256m,mode=1777", "grafana/loki@sha256:0db216b630ae1f348a1584c67f3cead8b4c1fc839169a39501db664744158e28", "-config.file=/etc/loki/local-config.yaml", fmt.Sprintf("-server.http-listen-port=%d", lokiPort), "-server.http-listen-address=127.0.0.1", "-auth.enabled=false", "-ingester.wal-dir=/loki/wal")
	waitHTTP(t, opa+"/health")
	waitHTTP(t, loki+"/ready")
	tenants := fmt.Sprintf("tenants:\n- name: appmana\n  id: fake\n  oidc:\n    clientID: appmana-logs\n    issuerURL: %s\n    usernameClaim: sub\n  opa:\n    url: %s/v1/data/appmana/workspace_logs/decision\n", issuer.URL, opa)
	must(t, os.WriteFile(filepath.Join(dir, "tenants.yaml"), []byte(tenants), 0644))
	must(t, os.WriteFile(filepath.Join(dir, "rbac.yaml"), []byte("roles: []\nroleBindings: []\n"), 0644))
	logFile, err := os.Create(filepath.Join(dir, "gateway.log"))
	must(t, err)
	cmd := exec.Command(binary, "--tenants.config="+filepath.Join(dir, "tenants.yaml"), "--rbac.config="+filepath.Join(dir, "rbac.yaml"), fmt.Sprintf("--web.listen=127.0.0.1:%d", gatewayPort), fmt.Sprintf("--web.internal.listen=127.0.0.1:%d", internalPort), fmt.Sprintf("--web.healthchecks.url=http://127.0.0.1:%d", gatewayPort), "--logs.read.endpoint="+loki, "--logs.tail.endpoint="+loki)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	must(t, cmd.Start())
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait(); logFile.Close() })
	gateway := fmt.Sprintf("http://127.0.0.1:%d", gatewayPort)
	waitHTTP(t, fmt.Sprintf("http://127.0.0.1:%d/ready", internalPort))
	ownerToken := token("owner", "appmana-logs", issuer.URL, time.Now().Add(time.Hour))
	base := gateway + "/api/logs/v1/appmana/loki/api/v1/"
	push(t, loki, "initial")
	get := func(path, bearer string, headers map[string]string) (int, string) {
		req, err := http.NewRequest(http.MethodGet, base+path, nil)
		must(t, err)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		res, err := http.DefaultClient.Do(req)
		must(t, err)
		defer res.Body.Close()
		b, err := io.ReadAll(res.Body)
		must(t, err)
		return res.StatusCode, string(b)
	}
	for name, bearer := range map[string]string{
		"unauthenticated": "", "wrong-audience": token("owner", "website", issuer.URL, time.Now().Add(time.Hour)),
		"wrong-issuer": token("owner", "appmana-logs", issuer.URL+"/other", time.Now().Add(time.Hour)),
		"expired":      token("owner", "appmana-logs", issuer.URL, time.Now().Add(-time.Minute)),
	} {
		t.Run(name, func(t *testing.T) {
			status, body := get("labels", bearer, nil)
			if status != 401 {
				t.Fatalf("expected 401, got %d %s", status, body)
			}
		})
	}
	t.Run("unrelated-user", func(t *testing.T) {
		status, body := get("labels", token("outsider", "appmana-logs", issuer.URL, time.Now().Add(time.Hour)), nil)
		if status != 403 {
			t.Fatalf("expected 403, got %d %s", status, body)
		}
	})
	t.Run("signed-cluster-admin-can-read-operational-namespaces", func(t *testing.T) {
		status, body := get("label/namespace/values", token("operator", "appmana-logs", issuer.URL, time.Now().Add(time.Hour), "cluster-admin"), nil)
		if status != 200 || !strings.Contains(body, "other-build") {
			t.Fatalf("expected operational access, got %d %s", status, body)
		}
	})
	t.Run("forged-group-headers-cannot-grant-admin", func(t *testing.T) {
		status, body := get("label/namespace/values", ownerToken, map[string]string{"X-Forwarded-Groups": "cluster-admin", "X-Auth-Request-Groups": "cluster-admin"})
		if status != 200 || strings.Contains(body, "other-build") {
			t.Fatalf("headers changed resource scope: %d %s", status, body)
		}
	})
	t.Run("admin-claim-with-wrong-audience-is-rejected", func(t *testing.T) {
		status, body := get("labels", token("operator", "website", issuer.URL, time.Now().Add(time.Hour), "cluster-admin"), nil)
		if status != 401 {
			t.Fatalf("expected 401, got %d %s", status, body)
		}
	})
	t.Run("post-body-cannot-bypass-selector-enforcement", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, base+"series", strings.NewReader(url.Values{"match[]": {`{namespace="other-build"}`}}.Encode()))
		must(t, err)
		req.Header.Set("Authorization", "Bearer "+ownerToken)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res, err := http.DefaultClient.Do(req)
		must(t, err)
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		must(t, err)
		if res.StatusCode != 405 {
			t.Fatalf("expected method rejection, got %d %s", res.StatusCode, body)
		}
	})
	t.Run("push-not-exposed", func(t *testing.T) {
		status, body := get("push", ownerToken, nil)
		if status != 404 {
			t.Fatalf("unexpected write route %d %s", status, body)
		}
	})
	t.Run("unknown-tenant", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, gateway+"/api/logs/v1/other/loki/api/v1/labels", nil)
		req.Header.Set("Authorization", "Bearer "+ownerToken)
		res, err := http.DefaultClient.Do(req)
		must(t, err)
		defer res.Body.Close()
		if res.StatusCode < 400 {
			t.Fatalf("unexpected tenant access %d", res.StatusCode)
		}
	})
	for _, query := range []string{`{container="unity"}`, `{container="unity",namespace!="owner-control"}`, `{container="unity",namespace!~"owner-control"}`} {
		t.Run("range-"+query, func(t *testing.T) {
			status, body := get("query_range?"+url.Values{"query": {query}}.Encode(), ownerToken, map[string]string{"X-Scope-OrgID": "attacker"})
			if status != 200 || strings.Contains(body, "FORBIDDEN") || !strings.Contains(body, "ALLOWED") {
				t.Fatalf("range auth failed %d %s", status, body)
			}
		})
	}
	for _, path := range []string{"labels", "label/namespace/values", "series?" + url.Values{"match[]": {`{container="unity"}`, `{namespace="other-build"}`}}.Encode()} {
		t.Run(path, func(t *testing.T) {
			status, body := get(path, ownerToken, nil)
			if status != 200 || strings.Contains(body, "other-build") || strings.Contains(body, "forbidden_label") {
				t.Fatalf("metadata auth failed %d %s", status, body)
			}
		})
	}
	t.Run("tail", func(t *testing.T) {
		u := "ws" + strings.TrimPrefix(base, "http") + "tail?" + url.Values{"query": {`{container="unity"}`}, "start": {fmt.Sprint(time.Now().Add(-time.Second).UnixNano())}}.Encode()
		conn, response, err := websocket.DefaultDialer.Dial(u, http.Header{"Authorization": {"Bearer " + ownerToken}, "X-Scope-OrgID": {"attacker"}})
		if err != nil {
			t.Fatalf("tail: %v response=%v", err, response)
		}
		defer conn.Close()
		push(t, loki, "tail")
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, body, err := conn.ReadMessage()
		must(t, err)
		if strings.Contains(string(body), "FORBIDDEN") || !strings.Contains(string(body), "ALLOWED") {
			t.Fatalf("tail auth failed %s", body)
		}
	})
	t.Run("revoked-membership", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodDelete, opa+"/v1/data/kubernetes/workspacemembers/owner-control/owner", nil)
		res, err := http.DefaultClient.Do(req)
		must(t, err)
		res.Body.Close()
		status, body := get("labels", ownerToken, nil)
		if status != 403 {
			t.Fatalf("revocation failed %d %s", status, body)
		}
	})
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func port(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
func docker(t *testing.T, suffix string, args ...string) {
	t.Helper()
	name := fmt.Sprintf("appmana-log-auth-%d-%s", os.Getpid(), suffix)
	command := append([]string{"run", "--rm", "-d", "--name", name, "--network=host"}, args...)
	output, err := exec.Command("docker", command...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker: %v %s", err, output)
	}
	t.Cleanup(func() {
		if t.Failed() {
			output, _ := exec.Command("docker", "logs", name).CombinedOutput()
			t.Log(string(output))
		}
		exec.Command("docker", "rm", "-f", name).Run()
	})
}
func waitHTTP(t *testing.T, endpoint string) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		res, err := (&http.Client{Timeout: 3 * time.Second}).Get(endpoint)
		if err == nil {
			res.Body.Close()
			if res.StatusCode == 200 {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("not ready: %s", endpoint)
}
func push(t *testing.T, endpoint, suffix string) {
	t.Helper()
	now := fmt.Sprint(time.Now().UnixNano())
	data := map[string]any{"streams": []any{
		map[string]any{"stream": map[string]string{"namespace": "owner-build", "container": "unity"}, "values": [][]string{{now, "ALLOWED " + suffix}}},
		map[string]any{"stream": map[string]string{"namespace": "other-build", "container": "unity", "forbidden_label": "private"}, "values": [][]string{{now, "FORBIDDEN " + suffix}}},
	}}
	b, err := json.Marshal(data)
	must(t, err)
	res, err := http.Post(endpoint+"/loki/api/v1/push", "application/json", bytes.NewReader(b))
	must(t, err)
	defer res.Body.Close()
	if res.StatusCode != 204 {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("push %d %s", res.StatusCode, body)
	}
}
