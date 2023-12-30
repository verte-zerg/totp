# TOTP Package

This package provides a Go implementation of the Time-based One-time Password (TOTP) algorithm as described in [RFC 6238](https://tools.ietf.org/html/rfc6238).
The implementation supports following customizations:
- `SHA-1`, `SHA-256`, `SHA-512` hashing algorithms (default is `SHA-1`)
- up to `10` digits long codes (default is `6`)
- custom time step (default is `30` seconds)

The package doesn't have any external dependencies.

## Usage

First, import the package:

```go
import "github.com/verte-zerg/totp"
```

Create a new TOTP instance with a `base32` encoded secret
or use functions with secret as a parameter:

```go
SECRET := "YOUR_BASE32_ENCODED_SECRET"
totpInstance, err := totp.New(SECRET, nil)
if err != nil {
    // handle error
}
```

Generate a TOTP:
```go
code := totpInstance.Generate()
```

Verify a TOTP:
```go
isValid := totpInstance.Verify("123456")
```

You can also generate and verify TOTPs at a specific time:

```go
ts := time.Now()

code := totpInstance.GenerateAt(ts)
isValid := totpInstance.VerifyAt("123456", ts)
```

## Options
Options can be passed to the `New` function to customize the TOTP instance:

```go
options := &totp.Options{
    Digits:    6,                    // default is 6
    Algorithm: totp.SHA1,            // default is SHA1
    TimeStep:  30,                   // default is 30
}
totpInstance, err := totp.New(SECRET, options)
```

## Functions

- `New(secret string, options *Options) (*TOTP, error)`: Creates a new TOTP instance with the given `base32` encoded secret.
- `(t *TOTP) Generate() string`: Generates a TOTP using the current time.
- `(t *TOTP) GenerateAt(timestamp time.Time) string`: Generates a TOTP at the given time.
- `(t *TOTP) Verify(code string) bool`: Verifies a TOTP using the current time.
- `(t *TOTP) VerifyAt(code string, timestamp time.Time) bool`: Verifies a TOTP at the given time.

## Contributing

Contributions are welcome! Please submit a pull request or create an issue to get started.
