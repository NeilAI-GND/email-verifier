package emailverifier

import (
	"net"
	"strings"
)

// CheckSPF checks if the domain has a valid SPF record.
func (v *Verifier) CheckSPF(domain string) bool {
	domain = domainToASCII(domain)
	records, err := net.LookupTXT(domain)
	if err != nil {
		return false
	}
	for _, record := range records {
		if strings.HasPrefix(strings.ToLower(record), "v=spf1") {
			return true
		}
	}
	return false
}

// CheckDMARC checks if the domain has a valid DMARC record.
func (v *Verifier) CheckDMARC(domain string) bool {
	domain = domainToASCII(domain)
	records, err := net.LookupTXT("_dmarc." + domain)
	if err != nil {
		return false
	}
	for _, record := range records {
		if strings.HasPrefix(strings.ToLower(record), "v=dmarc1") {
			return true
		}
	}
	return false
}
