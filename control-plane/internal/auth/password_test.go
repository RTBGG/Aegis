package auth

import "testing"

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if hash == "" {
		t.Fatal("empty hash")
	}
	ok, err := VerifyPassword("correct horse battery staple", hash)
	if err != nil || !ok {
		t.Fatalf("verify correct password: ok=%v err=%v", ok, err)
	}
	bad, err := VerifyPassword("wrong password", hash)
	if err != nil {
		t.Fatalf("verify wrong password err: %v", err)
	}
	if bad {
		t.Fatal("wrong password verified as correct")
	}
}

func TestHashesAreSalted(t *testing.T) {
	a, _ := HashPassword("same")
	b, _ := HashPassword("same")
	if a == b {
		t.Fatal("identical hashes for same password (salt not applied)")
	}
}
