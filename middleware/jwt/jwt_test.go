package mdjwt

import (
	"errors"
	"fmt"
	"github.com/jeffotoni/quick/context"
	"net/http"
	"testing"

	"github.com/golang-jwt/jwt/v4"
)

// go test -v -failfast -run  ^Test_jwtKeyFunc$
func Test_jwtKeyFunc(t *testing.T) {
	type args struct {
		config Config
	}
	tests := []struct {
		name string
		args args
		want jwt.Keyfunc
	}{
		{
			name: "Fail unexpected jwt signing method=%v",
			args: args{
				config: Config{
					Quick: &quickCtx.Ctx{
						Response: nil,
						JsonStr:  "",
						Headers: map[string][]string{
							"": {},
						},
						Params: map[string]string{
							"": "",
						},
						Query: map[string]string{
							"": "",
						},
					},
					SigningMethod:  "",
					SuccessHandler: nil,
					ErrorHandler:   nil,
					SigningKey:     nil,
					SigningKeys: map[string]interface{}{
						"": nil,
					},
				},
			},
			want: func(t *jwt.Token) (interface{}, error) {
				return nil, fmt.Errorf("unexpected jwt signing method=%v", t.Header["alg"])
			},
		},
		{
			name: `unexpected jwt key id=%v", t.Header["kid"]`,
			args: args{
				config: Config{
					Quick: &quickCtx.Ctx{
						Response: nil,
						JsonStr:  "",
						Headers: map[string][]string{
							"": {},
						},
						Params: map[string]string{
							"": "",
						},
						Query: map[string]string{
							"": "",
						},
					},
					SigningMethod:  HS256,
					SuccessHandler: nil,
					ErrorHandler:   nil,
					SigningKey:     nil,
					SigningKeys: map[string]interface{}{
						"": nil,
					},
				},
			},
			want: func(t *jwt.Token) (interface{}, error) {
				return nil, fmt.Errorf("unexpected jwt key id=%v", t.Header["kid"])
			},
		},
		{
			name: "ok",
			args: args{
				config: Config{
					Quick: &quickCtx.Ctx{
						Response: nil,
						JsonStr:  "",
						Headers: map[string][]string{
							"": {},
						},
						Params: map[string]string{
							"": "",
						},
						Query: map[string]string{
							"": "",
						},
					},
					SigningMethod:  HS256,
					SuccessHandler: nil,
					ErrorHandler:   nil,
					SigningKey:     nil,
					SigningKeys: map[string]interface{}{
						"batata": struct{}{},
					},
				},
			},
			want: func(t *jwt.Token) (interface{}, error) {
				return struct{}{}, nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := jwtKeyFunc(tt.args.config)

			token := jwt.New(jwt.SigningMethodHS256)
			for k := range tt.args.config.SigningKeys {
				token.Header["kid"] = k
			}

			iG, errG := got(token)
			iW, errW := tt.want(token)
			if iG != iW {
				t.Errorf("jwtKeyFunc non match item |%v| |%v|", iG, iW)
				return
			}
			if errG != nil {
				if errG.Error() != errW.Error() {
					t.Errorf("jwtKeyFunc non match item |%v| |%v|", errG, errW)
				}
			}
		})
	}
}

// go test -v -failfast -run ^Test_jwtFromHeader$
func Test_jwtFromHeader(t *testing.T) {
	type args struct {
		c          *quickCtx.Ctx
		header     string
		authScheme string
	}
	tests := []struct {
		name string
		args args
		want func(c *quickCtx.Ctx) (string, error)
	}{
		{
			name: "missing or malformed JWT",
			args: args{
				c: &quickCtx.Ctx{
					Response: nil,
					Request:  &http.Request{},
					JsonStr:  "",
					Headers: map[string][]string{
						"": {},
					},
					Params: map[string]string{
						"": "",
					},
					Query: map[string]string{
						"": "",
					},
				},
				header:     "",
				authScheme: "",
			},
			want: func(*quickCtx.Ctx) (string, error) {
				return "", errors.New("missing or malformed JWT")
			},
		},
		{
			name: "missing or malformed JWT",
			args: args{
				c: &quickCtx.Ctx{
					Response: nil,
					Request: &http.Request{
						Header: map[string][]string{
							"FRITA": []string{"BATATAAUTH"},
						},
					},
					JsonStr: "",
					Headers: map[string][]string{
						"": {},
					},
					Params: map[string]string{
						"": "",
					},
					Query: map[string]string{
						"": "",
					},
				},
				header:     "FRITA",
				authScheme: "BATATAAUTH",
			},
			want: func(*quickCtx.Ctx) (string, error) {
				return "", nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := jwtFromHeader(tt.args.header, tt.args.authScheme)

			iG, errG := got(tt.args.c)
			iW, errW := tt.want(tt.args.c)
			if iG != iW {
				t.Errorf("jwtFromHeader non match item |%v| |%v|", iG, iW)
				return
			}
			if errG != nil {
				if errG.Error() != errW.Error() {
					t.Errorf("jwtFromHeader non match item |%v| |%v|", errG, errW)
				}
			}
		})
	}
}
