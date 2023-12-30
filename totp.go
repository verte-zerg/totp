package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
	"strings"
	"time"
)

type Algorithm string

const (
	SHA1   Algorithm = "sha1" // default
	SHA256 Algorithm = "sha256"
	SHA512 Algorithm = "sha512"
)

var (
	ErrDecodingBase32Secret = errors.New("error decoding base32 secret")
	ErrTooManyDigits        = errors.New("too many digits")
	ErrUnknownHashAlgorithm = errors.New("unknown hash algorithm")
)

const (
	// DefaultDigits is the default number of digits in a generated code
	DefaultDigits = 6
	// Default period is the default number of seconds a code is valid
	DefaultPeriod = 30
	// DefaultAlgorithm is the default algorithm used to generate codes
	DefaultAlgorithm = SHA1
)

var hashFunctions = map[Algorithm]func() hash.Hash{
	SHA1:   sha1.New,
	SHA256: sha256.New,
	SHA512: sha512.New,
}

// TOTP is a Time-based One-time Password algorithm implementation
// as described in RFC 6238.
// For creating use New(secret string, options *Options) (*TOTP, error)
type TOTP struct {
	Secret    []byte
	ALgorithm Algorithm
	Digits    uint
	Period    uint
	HashFunc  func() hash.Hash
}

type Options struct {
	Algorithm Algorithm // The algorithm used to generate codes. Can be SHA1, SHA256 or SHA512. Default: SHA1
	Digits    uint      // The number of digits in a generated code. Must be between 1 and 10. Default: 6
	Period    uint      // The number of seconds a code is valid. Default: 30
}

// Create a new TOTP instance
// secret is the shared secret used to generate codes, encoded as base32 string
// options is an optional struct for configuring the TOTP with the following fields:
// - Algorithm: The algorithm used to generate codes. Can be SHA1, SHA256 or SHA512. Default: SHA1
// - Digits: The number of digits in a generated code. Must be between 1 and 10. Default: 6
// - Period: The number of seconds a code is valid. Default: 30
func New(secret string, options *Options) (*TOTP, error) {
	s := strings.ToUpper(strings.TrimSpace(secret))

	// Add padding to the base32 string if needed
	padding := len(s) % 8
	if padding != 0 {
		s += strings.Repeat("=", 8-padding)
	}

	decodedSecret, err := base32.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, ErrDecodingBase32Secret
	}

	if options == nil {
		options = &Options{}
	}

	algorithm := options.Algorithm
	if algorithm == "" {
		algorithm = DefaultAlgorithm
	}

	hashFunc, ok := hashFunctions[algorithm]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownHashAlgorithm, algorithm)
	}

	// Create a new function that returns hash function, which incapsulates the secret
	secretHashFunc := func() hash.Hash {
		return hmac.New(hashFunc, decodedSecret)
	}

	digits := options.Digits
	if digits > 10 {
		return nil, fmt.Errorf("%w: %d", ErrTooManyDigits, digits)
	}

	if digits == 0 {
		digits = DefaultDigits
	}

	period := options.Period
	if period == 0 {
		period = DefaultPeriod
	}

	return &TOTP{
		Secret:    decodedSecret,
		ALgorithm: algorithm,
		Digits:    digits,
		Period:    period,
		HashFunc:  secretHashFunc,
	}, nil
}

// Generate a TOTP code using the current time
func (t *TOTP) Generate() string {
	counter := uint64(time.Now().Unix()) / uint64(t.Period)
	return generateTOTP(t.Digits, counter, t.HashFunc)
}

// Generate a TOTP code using the given time
// The timestamp must be a time.Time instance
func (t *TOTP) GenerateAt(timestamp time.Time) string {
	counter := uint64(timestamp.Unix()) / uint64(t.Period)
	return generateTOTP(t.Digits, counter, t.HashFunc)
}

// Verify a TOTP code using the current time
func (t *TOTP) Verify(code string) bool {
	counter := uint64(time.Now().Unix()) / uint64(t.Period)
	return generateTOTP(t.Digits, counter, t.HashFunc) == code
}

// Verify a TOTP code using the given time
// The timestamp must be a time.Time instance
func (t *TOTP) VerifyAt(code string, timestamp time.Time) bool {
	counter := uint64(timestamp.Unix()) / uint64(t.Period)
	return generateTOTP(t.Digits, counter, t.HashFunc) == code
}

// Pad the given code with leading zeros
func padCode(code uint64, digits uint) string {
	f := fmt.Sprintf("%%0%dd", digits)
	return fmt.Sprintf(f, code)
}

// Generate a TOTP code
func generateTOTP(digits uint, counter uint64, hashFunc func() hash.Hash) string {
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)

	hf := hashFunc()
	hf.Write(counterBytes)
	hs := hf.Sum(nil)

	offset := hs[len(hs)-1] & 0xf
	binCode := uint64(hs[offset]&0x7f)<<24 | uint64(hs[offset+1]&0xff)<<16 | uint64(hs[offset+2]&0xff)<<8 | uint64(hs[offset+3])&0xff
	code := binCode % uint64(math.Pow10(int(digits)))

	return padCode(code, digits)
}
