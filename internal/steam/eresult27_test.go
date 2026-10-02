package steam

import (
	"context"
	"net/http"
	"testing"
)

func TestEresult27SurfacesAsDefinitive403(t *testing.T) {
	tr := fakeTransport(func(r *http.Request) (*http.Response, error) {
		return fakeResponse(200, "{}", http.Header{"X-Eresult": []string{"27"}}), nil
	})
	_, e := CallService(context.Background(), tr, "IAuthenticationService", "X", nil, "", "")
	api, ok := e.(*APIError)
	if !ok {
		t.Fatalf("want APIError got %T %v", e, e)
	}
	if api.Status != 403 || api.Code != "upstream_eresult_27" {
		t.Fatalf("got %d %s", api.Status, api.Code)
	}
}
