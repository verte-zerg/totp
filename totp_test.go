package totp

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

const (
	VALID_SECRET = "KRHVIUC7KRCVGVBB"
)

func TestGenerate(t *testing.T) {
	tests := []struct {
		secret string
		algo   Algorithm
		digits uint
		period uint
	}{
		{VALID_SECRET, SHA1, 10, 30},
		{VALID_SECRET, SHA1, 6, 30},
		{VALID_SECRET, SHA256, 6, 30},
		{VALID_SECRET, SHA512, 6, 30},
		{VALID_SECRET, SHA1, 8, 30},
		{VALID_SECRET, SHA1, 6, 60},
	}

	for _, test := range tests {
		name := fmt.Sprintf("%s-%d-%d", test.algo, test.digits, test.period)
		t.Run(name, func(t *testing.T) {
			totp, err := New(test.secret, &Options{
				Algorithm: test.algo,
				Digits:    test.digits,
				Period:    test.period,
			})
			if err != nil {
				t.Errorf("Expected no error, got %s", err)
			}
			code := totp.Generate()
			if len(code) != int(test.digits) {
				t.Errorf("Expected code length of %d, got %d", test.digits, len(code))
			}
		})
	}
}

func TestGenerateInvalidSecret(t *testing.T) {
	secret := "1234567890"
	_, err := New(secret, nil)
	if err != ErrDecodingBase32Secret {
		t.Errorf("Expected ErrDecodingBase32Secret, got %v", err)
	}
}

func TestGenerateInvalidDigits(t *testing.T) {
	secret := VALID_SECRET
	_, err := New(secret, &Options{Digits: 11})
	if !errors.Is(err, ErrTooManyDigits) {
		t.Errorf("Expected ErrTooManyDigits, got %v", err)
	}
}

func TestGenerateInvalidAlgorithm(t *testing.T) {
	secret := VALID_SECRET
	_, err := New(secret, &Options{Algorithm: "FOO"})
	if !errors.Is(err, ErrUnknownHashAlgorithm) {
		t.Errorf("Expected ErrUnknownHashAlgorithm, got %v", err)
	}
}

func TestGenerateAt(t *testing.T) {
	totp, err := New(VALID_SECRET, nil)
	if err != nil {
		t.Errorf("Expected no error, got %s", err)
	}

	tests := []struct {
		ts   int64
		code string
	}{
		{1703882207, "980239"},
		{1703882237, "552606"},
		{1703882267, "743299"},
		{1703882297, "334300"},
		{1703882327, "993457"},
	}

	for _, test := range tests {
		name := fmt.Sprintf("%d", test.ts)
		t.Run(name, func(t *testing.T) {
			code := totp.GenerateAt(time.Unix(test.ts, 0))
			if code != test.code {
				t.Errorf("Expected %s, got %s", test.code, code)
			}
			if len(code) != 6 {
				t.Errorf("Expected code length of 6, got %d", len(code))
			}
		})
	}
}

func TestVerify(t *testing.T) {
	tests := []struct {
		secret string
		algo   Algorithm
		digits uint
		period uint
	}{
		{VALID_SECRET, SHA1, 6, 30},
		{VALID_SECRET, SHA256, 6, 30},
		{VALID_SECRET, SHA512, 6, 30},
		{VALID_SECRET, SHA1, 8, 30},
		{VALID_SECRET, SHA1, 6, 60},
	}

	for _, test := range tests {
		name := fmt.Sprintf("%s-%d-%d", test.algo, test.digits, test.period)
		t.Run(name, func(t *testing.T) {
			totp, err := New(test.secret, &Options{
				Algorithm: test.algo,
				Digits:    test.digits,
				Period:    test.period,
			})
			if err != nil {
				t.Errorf("Expected no error, got %s", err)
			}
			code := totp.Generate()
			if !totp.Verify(code) {
				t.Errorf("Expected verification to pass")
			}
		})
	}
}

func TestVerifyAt(t *testing.T) {
	totp, err := New(VALID_SECRET, nil)
	if err != nil {
		t.Errorf("Expected no error, got %s", err)
	}

	tests := []struct {
		code   string
		ts     int64
		result bool
	}{
		{"980239", 1703882207, true},
		{"552606", 1703882237, true},
		{"743299", 1703882267, true},
		{"334300", 1703882297, true},
		{"993457", 1703882327, true},
		{"123456", 1703882206, false},
	}

	for _, test := range tests {
		name := fmt.Sprintf("%s-%d", test.code, test.ts)
		t.Run(name, func(t *testing.T) {
			if !totp.VerifyAt(test.code, time.Unix(test.ts, 0)) == test.result {
				t.Errorf("Expected verification to be %t", test.result)
			}
		})
	}
}

func TestPadCode(t *testing.T) {
	tests := []struct {
		code     uint64
		expected string
		digits   uint
	}{
		{0, "000000", 6},
		{1, "000001", 6},
		{12, "000012", 6},
		{123, "000123", 6},
		{1234, "001234", 6},
		{12345, "012345", 6},
		{123456, "123456", 6},
		{12345678, "12345678", 8},
		{12345678, "0012345678", 10},
		{1234567890, "1234567890", 10},
	}

	for _, test := range tests {
		name := fmt.Sprintf("%d-%d", test.code, test.digits)
		t.Run(name, func(t *testing.T) {
			actual := padCode(test.code, test.digits)
			if actual != test.expected {
				t.Errorf("Expected %s, got %s", test.expected, actual)
			}
		})
	}
}

func TestDefaultOptions(t *testing.T) {
	totp, err := New(VALID_SECRET, nil)
	if err != nil {
		t.Errorf("Expected no error, got %s", err)
	}
	if totp.Digits != 6 {
		t.Errorf("Expected default digits to be 6, got %d", totp.Digits)
	}
	if totp.Period != 30 {
		t.Errorf("Expected default period to be 30, got %d", totp.Period)
	}
	if totp.ALgorithm != SHA1 {
		t.Errorf("Expected default algorithm to be SHA1, got %s", totp.ALgorithm)
	}

	const (
		refTS   = 1703882207
		refCode = "980239"
	)

	// check if default algorithm is SHA1 using reference value
	code := totp.GenerateAt(time.Unix(refTS, 0))
	if code != refCode {
		t.Errorf("The default algorithm should be SHA1")
	}
}
