package main

import "testing"

func TestEnvBoolOr(t *testing.T) {
	t.Setenv("PF_TEST_BOOL", "")
	got, err := envBoolOr("PF_TEST_BOOL", true)
	if err != nil || !got {
		t.Fatalf("default true got=%v err=%v", got, err)
	}

	t.Setenv("PF_TEST_BOOL", "0")
	got, err = envBoolOr("PF_TEST_BOOL", true)
	if err != nil || got {
		t.Fatalf("0 should parse false got=%v err=%v", got, err)
	}

	t.Setenv("PF_TEST_BOOL", "1")
	got, err = envBoolOr("PF_TEST_BOOL", false)
	if err != nil || !got {
		t.Fatalf("1 should parse true got=%v err=%v", got, err)
	}

	t.Setenv("PF_TEST_BOOL", "nope")
	if _, err = envBoolOr("PF_TEST_BOOL", false); err == nil {
		t.Fatal("invalid bool should return error")
	}
}
