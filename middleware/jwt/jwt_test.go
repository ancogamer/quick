package mdjwt

import (
	"fmt"
	"github.com/jeffotoni/quick/context"

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
