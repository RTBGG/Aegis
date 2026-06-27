package challenge

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVerifyCaptcha(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		// Echo success only when secret + a non-empty response are presented.
		ok := r.Form.Get("secret") == "shh" && r.Form.Get("response") == "good-token"
		fmt.Fprintf(w, `{"success": %t}`, ok)
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 2 * time.Second}
	ctx := context.Background()

	if ok, err := verifyCaptcha(ctx, client, srv.URL, "shh", "good-token", "1.2.3.4"); err != nil || !ok {
		t.Fatalf("valid token should pass: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyCaptcha(ctx, client, srv.URL, "shh", "bad-token", ""); ok {
		t.Fatal("bad token should fail")
	}
	if ok, _ := verifyCaptcha(ctx, client, srv.URL, "wrong", "good-token", ""); ok {
		t.Fatal("wrong secret should fail")
	}
}

func TestProvidersKnown(t *testing.T) {
	for _, name := range []string{"turnstile", "hcaptcha", "recaptcha"} {
		p, ok := providers[name]
		if !ok || p.verifyURL == "" || p.fieldName == "" || p.widgetClass == "" || p.scriptURL == "" {
			t.Errorf("provider %q is incompletely defined: %+v", name, p)
		}
	}
}
