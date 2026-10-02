package server

import (
	"strings"
	"testing"
)

func TestLogAccessSanitizesPathAndNeverContainsSecrets(t *testing.T) {
	var captured string
	orig := logOutput
	logOutput = func(line string) { captured = line }
	defer func() { logOutput = orig }()

	logAccess("POST", "/v1/accounts/my-account/operations/session.credentials?x=1", 200, "", 0)
	if strings.Contains(captured, "?x=1") {
		t.Fatalf("query string leaked into log: %s", captured)
	}
	if !strings.Contains(captured, "/v1/accounts/my-account/operations/session.credentials") {
		t.Fatalf("path not logged in usable form: %s", captured)
	}
	if !strings.Contains(captured, "status=200") {
		t.Fatalf("status missing: %s", captured)
	}
	for _, forbidden := range []string{"Bearer ", "password", "access_token", "refresh_token", "shared_secret"} {
		if strings.Contains(strings.ToLower(captured), strings.ToLower(forbidden)) {
			t.Fatalf("log line contains forbidden substring %q: %s", forbidden, captured)
		}
	}
}
