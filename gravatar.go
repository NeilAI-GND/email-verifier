package emailverifier

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"
)

// Gravatar is detail about the Gravatar
type Gravatar struct {
	HasGravatar bool   `json:"has_gravatar"` // whether has gravatar
	GravatarUrl string `json:"gravatar_url"` // gravatar url
}

// CheckGravatar will return the Gravatar records for the given email.
func (v *Verifier) CheckGravatar(email string) (*Gravatar, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	emailMd5 := getMD5Hash(strings.ToLower(strings.TrimSpace(email)))
	gravatarUrl := gravatarBaseUrl + emailMd5 + "?d=404"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, gravatarUrl, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return &Gravatar{HasGravatar: false, GravatarUrl: ""}, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if getMD5Hash(string(body)) == gravatarDefaultMd5 {
		return &Gravatar{HasGravatar: false, GravatarUrl: ""}, nil
	}

	return &Gravatar{HasGravatar: true, GravatarUrl: gravatarUrl}, nil
}
