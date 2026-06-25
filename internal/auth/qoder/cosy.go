// Package qoder provides authentication and API client functionality
// for Qoder AI services. It handles OAuth2 device flow authentication,
// COSY hybrid-encryption signing, and direct API calls to the Qoder cloud.
package qoder

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// RSA public key for COSY encryption (from Qoder protocol).
// NOTE: This is a public protocol constant, not a secret. Hardcoded for convenience.
// Key rotation would require code changes and redeployment. If upstream rotates keys,
// this constant must be updated to match.
const qoderRSAPublicKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA8iMH5c02LilrsERw9t6Pv5Nc
4k6Pz1EaDicBMpdpxKduSZu5OANqUq8er4GM95omAGIOPOh+Nx0spthYA2BqGz+l
6HRkPJ7S236FZz73In/KVuLnwI8JJ2CbuJap8kvheCCZpmAWpb/cPx/3Vr/J6I17
XcW+ML9FoCI6AOvOzwIDAQAB
-----END PUBLIC KEY-----`

// UserInfo represents the encrypted user information payload
type UserInfo struct {
	UID                string `json:"uid"`
	SecurityOAuthToken string `json:"security_oauth_token"`
	Name               string `json:"name"`
	AID                string `json:"aid"`
	Email              string `json:"email"`
}

// CosyPayload represents the payload structure for COSY authentication
type CosyPayload struct {
	Version     string `json:"version"`
	RequestID   string `json:"requestId"`
	Info        string `json:"info"`
	CosyVersion string `json:"cosyVersion"`
	IdeVersion  string `json:"ideVersion"`
}

// CosyHeaders holds the generated COSY authentication headers, matching the
// header set the official qodercli v1.0.20 sends.
type CosyHeaders struct {
	Authorization string

	// Cosy-* headers
	CosyKey             string
	CosyUser            string
	CosyDate            string
	CosyVersion         string
	CosyMachineID       string
	CosyMachineToken    string
	CosyMachineType     string
	CosyMachineOS       string
	CosyClientType      string
	CosyClientIP        string
	CosyDataPolicy      string
	CosyBusinessProduct string
	CosyBusinessType    string
	CosyScene           string
	CosyOrganizationID  string
	CosyOrgTags         string

	// W3C tracing header
	Traceparent string

	// X-* and Login-* auxiliary headers
	LoginVersion string
}

// Apply writes the COSY headers onto an HTTP request. Caller is responsible for
// setting Content-Type and any non-auth headers (Accept, etc.).
func (h *CosyHeaders) Apply(req *http.Request) {
	if h == nil || req == nil {
		return
	}
	req.Header.Set("Authorization", h.Authorization)
	req.Header.Set("Cosy-Key", h.CosyKey)
	req.Header.Set("Cosy-User", h.CosyUser)
	req.Header.Set("Cosy-Date", h.CosyDate)
	req.Header.Set("Cosy-Version", h.CosyVersion)
	req.Header.Set("Cosy-Machineid", h.CosyMachineID)
	req.Header.Set("Cosy-Machinetoken", h.CosyMachineToken)
	req.Header.Set("Cosy-Machinetype", h.CosyMachineType)
	req.Header.Set("Cosy-Machineos", h.CosyMachineOS)
	req.Header.Set("Cosy-Clienttype", h.CosyClientType)
	req.Header.Set("Cosy-Clientip", h.CosyClientIP)
	req.Header.Set("Cosy-Data-Policy", h.CosyDataPolicy)
	if h.CosyBusinessProduct != "" {
		req.Header.Set("Cosy-Business-Product", h.CosyBusinessProduct)
	}
	if h.CosyBusinessType != "" {
		req.Header.Set("Cosy-Business-Type", h.CosyBusinessType)
	}
	if h.CosyScene != "" {
		req.Header.Set("Cosy-Scene", h.CosyScene)
	}
	if h.CosyOrganizationID != "" {
		req.Header.Set("Cosy-Organization-Id", h.CosyOrganizationID)
	}
	if h.CosyOrgTags != "" {
		req.Header.Set("Cosy-Organization-Tags", h.CosyOrgTags)
	}
	if h.Traceparent != "" {
		req.Header.Set("Traceparent", h.Traceparent)
	}
	req.Header.Set("Login-Version", h.LoginVersion)
}

// parseRSAPublicKey parses the PEM-encoded RSA public key.
func parseRSAPublicKey(pemString string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemString))
	if block == nil {
		return nil, fmt.Errorf("failed to decode RSA public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
	}
	pubKey, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	return pubKey, nil
}

// cosyPublicKey lazily parses qoderRSAPublicKey once and caches the result.
// The PEM bytes are a compile-time constant so the parse is deterministic;
// caching avoids repeating PEM decode + ASN.1 parse on every signed request.
var (
	cosyPublicKeyOnce sync.Once
	cosyPublicKey     *rsa.PublicKey
	cosyPublicKeyErr  error
)

func getCosyPublicKey() (*rsa.PublicKey, error) {
	cosyPublicKeyOnce.Do(func() {
		cosyPublicKey, cosyPublicKeyErr = parseRSAPublicKey(qoderRSAPublicKey)
	})
	return cosyPublicKey, cosyPublicKeyErr
}

// generateAESKey returns a 16-byte AES-128 key derived from a fresh UUID.
// Matches Veria/qodercli convention: uuid.New().String()[:16] — the first 16
// chars of the canonical UUID string include hyphens (e.g. "ad24345f-1a3e-4").
func generateAESKey() string {
	id := uuid.New().String()
	return id[:16]
}

// aesEncryptCBCBase64 encrypts plaintext with AES-128-CBC.
// SECURITY NOTE: The IV reuses the raw 16-byte key (matches qodercli protocol).
// This is cryptographically weak — IVs should be random and independent from keys.
// However, this matches the upstream Qoder protocol requirement. The key is fresh
// per request (UUID-based), so each request uses a unique (key, IV) pair.
// Fixing this would require upstream protocol changes.
func aesEncryptCBCBase64(plaintext, keyStr string) (string, error) {
	keyBytes := []byte(keyStr)
	if len(keyBytes) != 16 {
		return "", fmt.Errorf("aes key must be 16 bytes, got %d", len(keyBytes))
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", fmt.Errorf("aes cipher: %w", err)
	}
	padded, err := pkcs7Pad([]byte(plaintext), block.BlockSize())
	if err != nil {
		return "", fmt.Errorf("pkcs7 pad: %w", err)
	}
	iv := keyBytes[:16]
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// rsaEncryptBase64 RSA-PKCS1v15 encrypts data with the cached server public key
// and returns the base64-encoded ciphertext.
func rsaEncryptBase64(data []byte) (string, error) {
	pubKey, err := getCosyPublicKey()
	if err != nil {
		return "", err
	}
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, data)
	if err != nil {
		return "", fmt.Errorf("rsa encrypt: %w", err)
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// encryptUserInfo serializes the user info, AES-encrypts it, and RSA-encrypts
// the AES key. Returns (cosyKey, info) where:
//   - cosyKey = base64(RSA(aes_key))
//   - info    = base64(AES-128-CBC(json(user_info)))
func encryptUserInfo(userInfo *UserInfo) (string, string, error) {
	aesKey := generateAESKey()
	plaintext, err := json.Marshal(userInfo)
	if err != nil {
		return "", "", fmt.Errorf("marshal user info: %w", err)
	}
	infoB64, err := aesEncryptCBCBase64(string(plaintext), aesKey)
	if err != nil {
		return "", "", err
	}
	cosyKeyB64, err := rsaEncryptBase64([]byte(aesKey))
	if err != nil {
		return "", "", err
	}
	return cosyKeyB64, infoB64, nil
}

// pkcs7Pad applies PKCS7 padding to data
func pkcs7Pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 || blockSize > 255 {
		return nil, fmt.Errorf("invalid block size: %d", blockSize)
	}

	padding := blockSize - len(data)%blockSize
	padText := bytesRepeat(byte(padding), padding)
	return append(data, padText...), nil
}

// bytesRepeat creates a byte slice with the given byte repeated count times
func bytesRepeat(b byte, count int) []byte {
	result := make([]byte, count)
	for i := range result {
		result[i] = b
	}
	return result
}

// CosyCredentials holds the per-account inputs needed to sign a COSY request.
// Build it once per call from the live token storage and pass it into
// BuildAuthHeaders.
type CosyCredentials struct {
	UserID    string
	AuthToken string
	Name      string
	Email     string
	MachineID string
}

// FromStorage populates CosyCredentials from the persisted QoderTokenStorage.
func (c *CosyCredentials) FromStorage(s *QoderTokenStorage) {
	if c == nil || s == nil {
		return
	}
	c.UserID = s.UserID
	c.AuthToken = s.Token
	c.Name = s.Name
	c.Email = s.Email
	c.MachineID = s.MachineID
}

// computeSigPath extracts the signing path from a request URL by:
//  1. taking the path portion (drops scheme, host, query)
//  2. stripping the leading "/algo" prefix if present
//
// Matches qodercli convention: sigPath = path_after_host, with leading /algo
// removed. Empty input returns empty string.
func computeSigPath(requestURL string) (string, error) {
	parsed, err := url.Parse(requestURL)
	if err != nil {
		return "", fmt.Errorf("parse request URL: %w", err)
	}
	sigPath := parsed.Path
	if strings.HasPrefix(sigPath, "/algo") {
		sigPath = sigPath[len("/algo"):]
	}
	return sigPath, nil
}

// BuildAuthHeaders signs a single Qoder request using the COSY scheme used by
// the official qodercli (v0.14+). The body argument MUST be the exact bytes
// the request will send — both sigInput and Cosy-Bodyhash are computed from
// it. For GET requests pass nil or empty.
//
// Reference: github.com/Ve-ria/CLIProxyAPIPlus internal/runtime/executor/qoder_executor.go
// (commits e0f1c968 + d72fa22b — MD5 hash, full Cosy-* header set).
func BuildAuthHeaders(body []byte, requestURL string, creds CosyCredentials) (*CosyHeaders, error) {
	if creds.UserID == "" {
		return nil, fmt.Errorf("cosy: user id is empty")
	}
	if creds.AuthToken == "" {
		return nil, fmt.Errorf("cosy: auth token is empty")
	}

	cosyKey, infoB64, err := encryptUserInfo(&UserInfo{
		UID:                creds.UserID,
		SecurityOAuthToken: creds.AuthToken,
		Name:               creds.Name,
		AID:                "",
		Email:              creds.Email,
	})
	if err != nil {
		return nil, fmt.Errorf("encrypt user info: %w", err)
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	requestID := uuid.New().String()

	payloadJSON, err := json.Marshal(&CosyPayload{
		Version:     "v1",
		RequestID:   requestID,
		Info:        infoB64,
		CosyVersion: QoderIDEVersion,
		IdeVersion:  "",
	})
	if err != nil {
		return nil, fmt.Errorf("marshal cosy payload: %w", err)
	}
	payloadB64 := base64.StdEncoding.EncodeToString(payloadJSON)

	sigPath, err := computeSigPath(requestURL)
	if err != nil {
		return nil, err
	}

	bodyForSig := string(body)
	sigInput := fmt.Sprintf("%s\n%s\n%s\n%s\n%s", payloadB64, cosyKey, timestamp, bodyForSig, sigPath)
	sig := fmt.Sprintf("%x", md5.Sum([]byte(sigInput)))

	machineID := creds.MachineID
	if machineID == "" {
		machineID = generateMachineID()
	}

	// Generate W3C traceparent header for distributed tracing
	traceID := uuid.New().String()
	spanID := uuid.New().String()[:16]
	traceparent := fmt.Sprintf("00-%s-%s-01", traceID, spanID)

	return &CosyHeaders{
		Authorization:       fmt.Sprintf("Bearer COSY.%s.%s", payloadB64, sig),
		CosyKey:             cosyKey,
		CosyUser:            creds.UserID,
		CosyDate:            timestamp,
		CosyVersion:         QoderIDEVersion,
		CosyMachineID:       machineID,
		CosyMachineToken:    machineID,
		CosyMachineType:     QoderMachineTypeMagic,
		CosyMachineOS:       QoderMachineOS,
		CosyClientType:      QoderClientType,
		CosyClientIP:        machineID, // Note: Real client sends machine ID here, not actual IP
		CosyDataPolicy:      QoderDataPolicy,
		CosyBusinessProduct: "cli",
		CosyBusinessType:    "agent",
		CosyScene:           "assistant",
		CosyOrganizationID:  "",
		CosyOrgTags:         "",
		Traceparent:         traceparent,
		LoginVersion:        QoderLoginVersion,
	}, nil
}

// generateDeviceCodeVerifier generates a PKCE code verifier
func generateDeviceCodeVerifier() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// generateDeviceCodeChallenge creates a SHA-256 hash of the code verifier
func generateDeviceCodeChallenge(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// generateDevicePKCEPair creates a new code verifier and its corresponding code challenge
func generateDevicePKCEPair() (string, string, error) {
	codeVerifier, err := generateDeviceCodeVerifier()
	if err != nil {
		return "", "", err
	}
	codeChallenge := generateDeviceCodeChallenge(codeVerifier)
	return codeVerifier, codeChallenge, nil
}

// generateMachineID generates a random machine UUID. The result is persisted
// in the auth JSON file via QoderTokenStorage.MachineID after device flow
// login, so subsequent requests reuse the same identity from the auth file.
// This function is only called when no machine_id exists yet (first login or
// fallback when auth record is missing the field).
func generateMachineID() string {
	return uuid.New().String()
}

// formatExpiresAt converts milliseconds epoch to RFC3339 format
func formatExpiresAt(expireMs int64) string {
	return time.Unix(0, expireMs*int64(time.Millisecond)).Format(time.RFC3339)
}

// parseExpiresAt converts a Qoder upstream expiry hint into Unix
// milliseconds. The hint can be:
//
//   - an RFC3339 timestamp (e.g. "2026-06-16T07:15:04Z")
//   - a Unix-millisecond integer string (e.g. "1781594470000")
//   - empty / unparseable, in which case it falls back to a positive
//     expiresInSeconds (seconds from now), and finally to "now + 30 days"
//     when neither is provided.
func parseExpiresAt(s string, expiresInSeconds int64) int64 {
	s = strings.TrimSpace(s)
	if s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t.UnixMilli()
		}
		if ms, err := strconv.ParseInt(s, 10, 64); err == nil && ms > 0 {
			return ms
		}
	}
	if expiresInSeconds > 0 {
		return time.Now().Add(time.Duration(expiresInSeconds) * time.Second).UnixMilli()
	}
	return time.Now().Add(30 * 24 * time.Hour).UnixMilli()
}
