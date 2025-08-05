package certificates_test

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"gitlab.lila.network/lila-network/certwarden-deploy/internal/certificates"
	"gitlab.lila.network/lila-network/certwarden-deploy/internal/configuration"
	"gitlab.lila.network/lila-network/certwarden-deploy/internal/constants"
)

func TestFetchDataFromServer_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := constants.CertificateApiPath + "testCert"
		if r.URL.Path != expectedPath {
			t.Errorf("expected path %q, got %q", expectedPath, r.URL.Path)
		}
		if got := r.Header.Get(constants.ApiKeyHeaderName); got != "hunter2" {
			t.Errorf("expected API-Key hunter2, got %q", got)
		}
		fmt.Fprint(w, "hello")
	}))
	defer ts.Close()

	cm := certificates.CertificateManager{
		Config:     &configuration.ConfigFileData{BaseURL: ts.URL},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{})),
		HTTPClient: ts.Client(),
	}
	c := &certificates.CertificateData{
		Type:   certificates.CertificateFile,
		Name:   "testCert",
		Secret: "hunter2",
	}

	err := cm.FetchDataFromServer(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := string(c.ServerBytes)
	if got != "hello" {
		t.Errorf("expected body %q, got %q", "hello", got)
	}
}

func TestFetchDataFromServer_Unauthorized(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	cm := certificates.CertificateManager{
		Config:     &configuration.ConfigFileData{BaseURL: ts.URL},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{})),
		HTTPClient: ts.Client(),
	}
	c := &certificates.CertificateData{
		Type:   certificates.KeyFile,
		Name:   "mykey",
		Secret: "badsecret",
	}

	err := cm.FetchDataFromServer(c)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, certificates.ErrAPIKeyInvalid) {
		t.Errorf("expected API-Key invalid error, got %v", err)
	}
	if c.ServerBytes != nil {
		t.Errorf("expected no data on unauthorized, got %v", c.ServerBytes)
	}
}
