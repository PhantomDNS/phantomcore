package utils

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net"
)

var secret []byte

func InitSecret(base64Key string) error {
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return err
	}
	secret = key
	return nil
}

// AnonymizeIP masks an IP address for privacy, with optional hashing.
// - IPv4: zeroes last octet
// - IPv6: zeroes last 80 bits
// If a secret is provided, the masked IP is hashed with it.
func AnonymizeIP(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}

	// Normalize to 16-byte form
	ip = ip.To16()

	if ip.To4() != nil {
		// IPv4 → mask last octet
		ip = ip.To4()
		ip[3] = 0
	} else {
		// IPv6 → mask last 10 bytes (80 bits)
		for i := 6; i < 16; i++ {
			ip[i] = 0
		}
	}

	// If no secret → just return masked IP
	if len(secret) == 0 {
		return ip.String()
	}

	// If secret provided → hash masked IP
	h := hmac.New(sha256.New, secret)
	h.Write(ip)
	return hex.EncodeToString(h.Sum(nil))[:16] // first 16 chars
}
