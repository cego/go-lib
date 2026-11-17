package oidcauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

func (o *OidcAuth) revokeSession(ctx context.Context, token string) (string, error) {
	if len(token) > maxSessionCookieBytes {
		return token, errors.New("refresh token too large")
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*tokenRequestTimeout)
	defer cancel()
	tokens, err := o.refreshes.invalidate(ctx, token)
	if err != nil {
		return token, err
	}
	select {
	case o.tokenRequests <- struct{}{}:
		defer func() { <-o.tokenRequests }()
	default:
		return tokens[len(tokens)-1], errRefreshBusy
	}
	var failures []error
	var retry string
	for i := len(tokens) - 1; i >= 0; i-- {
		if err := o.revokeToken(ctx, tokens[i]); err != nil {
			if retry == "" {
				retry = tokens[i]
			}
			failures = append(failures, err)
		}
	}
	return retry, errors.Join(failures...)
}

func (o *OidcAuth) revokeToken(ctx context.Context, token string) error {
	ctx, cancel := context.WithTimeout(ctx, tokenRequestTimeout)
	defer cancel()
	form := url.Values{"token": {token}, "token_type_hint": {"refresh_token"}}
	if o.revocationAuth == oauth2.AuthStyleInParams {
		form.Set("client_id", o.oauth.ClientID)
		form.Set("client_secret", o.oauth.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.revocationURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if o.revocationAuth == oauth2.AuthStyleInHeader {
		req.SetBasicAuth(url.QueryEscape(o.oauth.ClientID), url.QueryEscape(o.oauth.ClientSecret))
	}
	client := *o.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("token revocation returned HTTP %d", res.StatusCode)
	}
	return nil
}
