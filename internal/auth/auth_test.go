package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_ValidHeader(t *testing.T) {
	headers := http.Header{}
	headers.Add("Authorization", "ApiKey mysecretkey123")

	apiKey, err := GetAPIKey(headers)

	if err != nil {
		t.Fatalf("Expected no error, but got: %v", err)
	}
	if apiKey != "mysecretkey123" {
		t.Errorf("Expected API key 'mysecretkey123', but got: '%s'", apiKey)
	}
}

func TestGetAPIKey_NoAuthHeader(t *testing.T) {
	headers := http.Header{} // Empty headers

	_, err := GetAPIKey(headers)

	if err == nil {
		t.Fatal("Expected an error, but got nil")
	}
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("Expected error '%v', but got '%v'", ErrNoAuthHeaderIncluded, err)
	}
}

func TestGetAPIKey_MalformedHeader_WrongScheme(t *testing.T) {
	headers := http.Header{}
	headers.Add("Authorization", "Bearer mysecretkey123") // Using "Bearer" instead of "ApiKey"

	_, err := GetAPIKey(headers)

	if err == nil {
		t.Fatal("Expected an error for malformed header, but got nil")
	}
	// You might want to check the specific error message if it's well-defined
	expectedErrMsg := "malformed authorization header"
	if err.Error() != expectedErrMsg {
		t.Errorf("Expected error message '%s', but got '%s'", expectedErrMsg, err.Error())
	}
}

func TestGetAPIKey_MalformedHeader_NoSpace(t *testing.T) {
	headers := http.Header{}
	headers.Add("Authorization", "ApiKeymysecretkey123") // No space after "ApiKey"

	_, err := GetAPIKey(headers)

	if err == nil {
		t.Fatal("Expected an error for malformed header, but got nil")
	}
	expectedErrMsg := "malformed authorization header"
	if err.Error() != expectedErrMsg {
		t.Errorf("Expected error message '%s', but got '%s'", expectedErrMsg, err.Error())
	}
}
