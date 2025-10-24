# JWT Package - Identity Token Generator

This package provides utilities for parsing and generating JWT identity tokens with email claims.

## Features

- **Parse JWT tokens** with or without signature verification
- **Generate identity tokens** with email claims
- RSA and HMAC signing support
- Flexible claims management
- Default test methods with singleton pattern (no key management needed!)
- Comprehensive validation options

## Quick Start

### Simple Identity Token (Testing)

For testing and development, use the convenient default methods:

```go
import (
    "time"
    "github.com/linuxfoundation/lfx-v2-auth-service/pkg/jwt"
)

// Super simple - just 2 parameters!
token, err := jwt.GenerateSimpleTestIdentityToken("user@example.com", time.Hour)
```

** WARNING:** Default test methods use a singleton test key and are **only for testing**. Never use in production!

## Generating Identity Tokens

### Production - With Your Own RSA Key

```go
import (
    "crypto/rsa"
    "time"
    "github.com/linuxfoundation/lfx-v2-auth-service/pkg/jwt"
)

func main() {
    // Load or generate your RSA private key
    var privateKey *rsa.PrivateKey
    // ... (load your key)

    // Generate identity token
    token, err := jwt.GenerateIdentityToken(
        "user@example.com",                      // email
        "https://yourapp.auth0.com/",            // issuer
        "https://yourapp.auth0.com/api/v2/",     // audience
        30*time.Minute,                          // expires in
        privateKey,                              // signing key
    )
    if err != nil {
        panic(err)
    }

    fmt.Println("Generated token:", token)
}
```

### Testing - With Default Key

```go
// Full control
token, err := jwt.GenerateTestIdentityToken(
    "user@example.com",
    "https://test.auth0.com/",
    "https://test.auth0.com/api/v2/",
    30*time.Minute,
)

// Minimal parameters (uses defaults)
token, err := jwt.GenerateSimpleTestIdentityToken("user@example.com", time.Hour)
```

### HMAC Signing (for testing)

```go
secret := []byte("your-secret-key")

// With custom config
token, err := jwt.GenerateHMACIdentityToken(
    "user@example.com",
    "test-issuer",
    "test-audience",
    30*time.Minute,
    secret,
)

// With default key
token, err := jwt.GenerateTestHMACIdentityToken(
    "user@example.com",
    "test-issuer",
    "test-audience",
    time.Hour,
)
```

### Advanced - Custom Claims

```go
import "github.com/lestrrat-go/jwx/v2/jwa"

opts := &jwt.GeneratorOptions{
    Email:         "user@example.com",
    Subject:       "auth0|123456789",           // Optional subject
    Issuer:        "https://myapp.com/",
    Audience:      "https://verify.myapp.com/",
    ExpiresIn:     15 * time.Minute,
    IssuedAt:      time.Now(),
    SigningMethod: jwa.RS256,
    SigningKey:    privateKey,
    CustomClaims: map[string]any{
        "verification_code": "ABC123",
        "purpose":           "email-verification",
        "tenant_id":         "tenant-456",
    },
}

token, err := jwt.Generate(opts)
```

## Parsing Tokens

### Parse Without Verification

```go
import "context"

ctx := context.Background()
claims, err := jwt.ParseUnverified(ctx, tokenString, jwt.DefaultParseOptions())
if err != nil {
    // Handle error
}

// Get email from claims
email, ok := claims.GetStringClaim("email")
fmt.Println("Email:", email)
```

### Parse With Verification

```go
var publicKey *rsa.PublicKey
// ... (load your public key)

opts := &jwt.ParseOptions{
    VerifySignature:   true,
    SigningKey:        publicKey,
    ExpectedIssuer:    "https://yourapp.auth0.com/",
    ExpectedAudience:  "https://yourapp.auth0.com/api/v2/",
    RequireExpiration: true,
    RequireSubject:    false, // Identity tokens may not have subject
}

claims, err := jwt.ParseVerified(ctx, tokenString, opts)
```

### Extract Custom Claims

```go
// Get email
email, ok := claims.GetStringClaim("email")

// Get verification code
code, ok := claims.GetStringClaim("verification_code")

// Get any custom claim
value, exists := claims.GetClaim("custom_field")
```

## Default Test Methods

Perfect for unit tests - no need to manage keys!

### Available Methods

```go
// RSA-signed with singleton test key
jwt.GenerateTestIdentityToken(email, issuer, audience, expiresIn)
jwt.GenerateSimpleTestIdentityToken(email, expiresIn)

// HMAC-signed with default secret
jwt.GenerateTestHMACIdentityToken(email, issuer, audience, expiresIn)

// Get the public key for verification
publicKey, err := jwt.GetDefaultTestPublicKey()
```

### Example: Unit Test

```go
func TestEmailVerification(t *testing.T) {
    // Generate test token in one line!
    token, err := jwt.GenerateSimpleTestIdentityToken("test@example.com", time.Hour)
    require.NoError(t, err)
    
    // Use it in your test
    result, err := emailService.VerifyEmail(token)
    require.NoError(t, err)
    assert.True(t, result.Verified)
}
```

### Example: Verify Test Tokens

```go
func TestTokenVerification(t *testing.T) {
    // Generate token
    token, _ := jwt.GenerateSimpleTestIdentityToken("user@test.com", time.Hour)
    
    // Get the public key
    publicKey, _ := jwt.GetDefaultTestPublicKey()
    
    // Verify
    ctx := context.Background()
    parseOpts := &jwt.ParseOptions{
        VerifySignature: true,
        SigningKey:      publicKey,
        RequireSubject:  false,
    }
    
    claims, err := jwt.ParseVerified(ctx, token, parseOpts)
    require.NoError(t, err)
}
```

## Use Cases

### Email Verification

```go
// Generate verification token with short expiration
token, err := jwt.GenerateIdentityToken(
    "newuser@example.com",
    "https://myapp.com/",
    "https://myapp.com/verify-email",
    15*time.Minute, // Short expiration for security
    privateKey,
)

// Send in verification email
emailLink := fmt.Sprintf("https://myapp.com/verify?token=%s", token)
```

### Password Reset

```go
// Generate reset token
opts := &jwt.GeneratorOptions{
    Email:         "user@example.com",
    Subject:       "user-id-123",
    Issuer:        "https://myapp.com/",
    Audience:      "https://myapp.com/reset-password",
    ExpiresIn:     30 * time.Minute,
    SigningKey:    privateKey,
    SigningMethod: jwa.RS256,
    CustomClaims: map[string]any{
        "reset_code": generateSecureCode(),
    },
}

token, err := jwt.Generate(opts)
```

### Account Linking

```go
// Generate token for linking alternate email
token, err := jwt.GenerateIdentityToken(
    "alternate@example.com",
    "https://myapp.com/",
    "https://myapp.com/link-email",
    1*time.Hour,
    privateKey,
)
```

## Helper Functions

### Option Builders

```go
// Create options with defaults
opts := jwt.IdentityTokenOptions("user@example.com", privateKey)
opts.Issuer = "https://myapp.com/"
opts.ExpiresIn = 15 * time.Minute

token, err := jwt.Generate(opts)
```

```go
// HMAC options
opts := jwt.HMACIdentityTokenOptions("user@example.com", secret)
token, err := jwt.Generate(opts)
```

## Complete Example

```go
package main

import (
    "context"
    "crypto/rand"
    "crypto/rsa"
    "fmt"
    "time"

    "github.com/linuxfoundation/lfx-v2-auth-service/pkg/jwt"
)

func main() {
    // Generate RSA key pair
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        panic(err)
    }
    publicKey := &privateKey.PublicKey

    // Generate identity token
    tokenString, err := jwt.GenerateIdentityToken(
        "user@example.com",
        "https://myapp.com/",
        "https://myapp.com/verify-email",
        15*time.Minute,
        privateKey,
    )
    if err != nil {
        panic(err)
    }

    fmt.Println("Generated token!")

    // Parse and verify
    ctx := context.Background()
    parseOpts := &jwt.ParseOptions{
        VerifySignature:   true,
        SigningKey:        publicKey,
        ExpectedIssuer:    "https://myapp.com/",
        ExpectedAudience:  "https://myapp.com/verify-email",
        RequireExpiration: true,
        RequireSubject:    false,
    }

    claims, err := jwt.ParseVerified(ctx, tokenString, parseOpts)
    if err != nil {
        panic(err)
    }

    email, _ := claims.GetStringClaim("email")
    fmt.Println("Verified email:", email)
}
```

## API Reference

### Generation Functions

| Function | Description | Use Case |
|----------|-------------|----------|
| `Generate(opts)` | Generate with full control | Custom claims, advanced config |
| `GenerateIdentityToken(...)` | Generate with RSA | Production use |
| `GenerateHMACIdentityToken(...)` | Generate with HMAC | Testing HMAC signatures |
| `GenerateTestIdentityToken(...)` | Generate with default RSA key | Testing with custom issuer |
| `GenerateSimpleTestIdentityToken(...)` | Generate with defaults | Quick testing |
| `GenerateTestHMACIdentityToken(...)` | Generate with default HMAC | Testing |

### Helper Functions

| Function | Returns | Description |
|----------|---------|-------------|
| `GetDefaultTestPublicKey()` | `*rsa.PublicKey` | Get singleton test public key |
| `IdentityTokenOptions(email, key)` | `*GeneratorOptions` | Create options with defaults |
| `HMACIdentityTokenOptions(email, secret)` | `*GeneratorOptions` | Create HMAC options |
| `DefaultGeneratorOptions()` | `*GeneratorOptions` | Get default options |

## Error Handling

```go
token, err := jwt.GenerateIdentityToken(...)
if err != nil {
    switch err.(type) {
    case errors.Validation:
        // Invalid input (missing email, bad key, etc.)
    case errors.Unexpected:
        // Signing/building failure
    }
}
```

## Important Notes

**Default test methods are for testing only!**
- Keys are generated once and reused
- Not secure for production
- Clearly marked with "Test" in function names

## Testing

```bash
# Run all tests
go test ./pkg/jwt/...

# Run with verbose output
go test -v ./pkg/jwt/...

# Run specific test
go test -v ./pkg/jwt/... -run TestGenerateSimpleTestIdentityToken
```
