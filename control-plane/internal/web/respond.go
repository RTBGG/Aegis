// Package web holds shared HTTP response/decode helpers used across handlers.
package web

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

const maxBody = 1 << 20 // 1 MiB

// JSON writes v as a JSON response with the given status.
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

// Error writes a structured error: {"error":{"code":...,"message":...}}.
func Error(w http.ResponseWriter, status int, code, message string) {
	JSON(w, status, map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}

// Decode reads a JSON body into dst with a size limit and unknown-field check.
func Decode(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("request body must contain a single JSON object")
	}
	return nil
}

// ReadAllString reads a small request body as a string.
func ReadAllString(r *http.Request) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	return string(b), err
}
