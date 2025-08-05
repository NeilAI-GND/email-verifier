package emailverifier

import (
	"crypto/md5" //nolint:gosec
	"encoding/hex"
	"reflect"
	"strings"

	"golang.org/x/net/idna"
)

// splitDomain splits domain and returns sld and tld
func splitDomain(domain string) (string, string) {
	parts := strings.Split(domain, ".")
	n := len(parts)
	if len(parts) >= 2 {
		return parts[n-2], parts[n-1]
	}
	return "", parts[0]
}

// domainToASCII converts any internationalized domain names to ASCII
// reference: https://en.wikipedia.org/wiki/Punycode
func domainToASCII(domain string) string {
	asciiDomain, err := idna.ToASCII(domain)
	if err != nil {
		return domain
	}
	return asciiDomain

}

// callJobFuncWithParams convert jobFunc and prams to a specific function and call it
func callJobFuncWithParams(jobFunc interface{}, params []interface{}) []reflect.Value {
	typ := reflect.TypeOf(jobFunc)
	if typ.Kind() != reflect.Func {
		return nil
	}
	f := reflect.ValueOf(jobFunc)
	if len(params) != f.Type().NumIn() {
		return nil
	}
	in := make([]reflect.Value, len(params))
	for k, param := range params {
		in[k] = reflect.ValueOf(param)
	}
	return f.Call(in)
}

// getMD5Hash encodes the given string with md5 and returns the hex string.
// #nosec G401 - md5 is acceptable here for non-cryptographic hashing
func getMD5Hash(str string) string {
	sum := md5.Sum([]byte(str))
	return hex.EncodeToString(sum[:])
}
