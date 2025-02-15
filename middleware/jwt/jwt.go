package mdjwt

import (
	"errors"
	"fmt"
	"github.com/jeffotoni/quick/context"
	"net/http"
	"reflect"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

func New(config ...Config) func(next http.Handler) http.Handler {

	// Return middleware handler
	return func(next http.Handler) http.Handler {
		cfg := makeCfg(config, next)

		extractors := cfg.getExtractors()

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			var auth string
			var err error
			for _, extractor := range extractors {
				auth, err = extractor(cfg.Quick)
				if auth != "" && err == nil {
					break
				}
			}
			if err != nil {
				cfg.internalErr = err
				cfg.HandlerError(next)
				return
			}
			var token *jwt.Token

			if _, ok := cfg.Claims.(jwt.MapClaims); ok {
				token, err = jwt.Parse(auth, cfg.KeyFunc)
			} else {
				t := reflect.ValueOf(cfg.Claims).Type().Elem()
				claims := reflect.New(t).Interface().(jwt.Claims)
				token, err = jwt.ParseWithClaims(auth, claims, cfg.KeyFunc)
			}
			if err == nil && token.Valid {
				cfg.internalErr = nil
				cfg.Handler(next)
				return
			}
			cfg.internalErr = err
			cfg.HandlerError(next)
		})
	}
}

type jwtExtractor func(c *quickCtx.Ctx) (string, error)

// jwtKeyFunc returns a function that returns signing key for given token.
func jwtKeyFunc(config Config) jwt.Keyfunc {
	return func(t *jwt.Token) (interface{}, error) {
		// Check the signing method
		if t.Method.Alg() != config.SigningMethod {
			return nil, fmt.Errorf("unexpected jwt signing method=%v", t.Header["alg"])
		}
		if len(config.SigningKeys) > 0 {
			if kid, ok := t.Header["kid"].(string); ok {
				if key, ok := config.SigningKeys[kid]; ok {
					return key, nil
				}
			}
			return nil, fmt.Errorf("unexpected jwt key id=%v", t.Header["kid"])
		}
		return config.SigningKey, nil
	}
}

// jwtFromHeader returns a function that extracts token from the request header.
func jwtFromHeader(header string, authScheme string) func(c *quickCtx.Ctx) (string, error) {
	return func(c *quickCtx.Ctx) (string, error) {
		auth := c.Request.Header.Get(header)
		l := len(authScheme)
		fmt.Println(c.Request.Header, auth, l+1, strings.EqualFold(auth[:l], authScheme))
		if len(auth) > l+1 && strings.EqualFold(auth[:l], authScheme) {
			return strings.TrimSpace(auth[l:]), nil
		}
		return "", errors.New("missing or malformed JWT")
	}
}

// jwtFromQuery returns a function that extracts token from the query string.
func jwtFromQuery(param string) func(c *quickCtx.Ctx) (string, error) {
	return func(c *quickCtx.Ctx) (string, error) {
		token := c.Request.URL.Query().Get(param)
		if token == "" {
			return "", errors.New("missing or malformed JWT")
		}
		return token, nil
	}
}

// jwtFromParam returns a function that extracts token from the url param string.
func jwtFromParam(param string) func(c *quickCtx.Ctx) (string, error) {
	return func(c *quickCtx.Ctx) (string, error) {
		token := c.Params[param]
		if token == "" {
			return "", errors.New("missing or malformed JWT")
		}
		return token, nil
	}
}

// jwtFromCookie returns a function that extracts token from the named cookie.
func jwtFromCookie(name string) func(c *quickCtx.Ctx) (string, error) {
	return func(c *quickCtx.Ctx) (string, error) {
		cookie, err := c.Request.Cookie(name)
		if err != nil {
			return "", err
		}

		if cookie.String() == "" {
			return "", errors.New("missing or malformed JWT")
		}
		return cookie.String(), nil
	}
}
