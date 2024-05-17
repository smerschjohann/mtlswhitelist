package mtlswhitelist

import (
	"net/http"
	"regexp"
	"testing"
)

func TestRuleHeader_Match(t *testing.T) {
	type fields struct {
		Headers        map[string]string
		allowedHeaders map[string]*regexp.Regexp
	}
	type args struct {
		req *http.Request
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "header match",
			fields: fields{
				Headers: map[string]string{
					"Custom-Header": ".*",
				},
			},
			args: args{
				req: &http.Request{
					Header: http.Header{
						"Custom-Header": []string{"value"},
					},
				},
			},
			want: true,
		},
		{
			name: "header not present is rejected",
			fields: fields{
				Headers: map[string]string{
					"Custom-Header": ".*",
				},
			},
			args: args{
				req: &http.Request{
					Header: http.Header{},
				},
			},
			want: false,
		},
		{
			name: "wrong header value is rejected",
			fields: fields{
				Headers: map[string]string{
					"Custom-Header": "somethingspecial.*",
				},
			},
			args: args{
				req: &http.Request{
					Header: http.Header{
						"Custom-Header": []string{"value"},
					},
				},
			},
			want: false,
		},
		{
			name: "multiple headers can be checked",
			fields: fields{
				Headers: map[string]string{
					"Custom-Header":  "somethingspecial.*",
					"Another-Header": ".*",
				},
			},
			args: args{
				req: &http.Request{
					Header: http.Header{
						"Custom-Header":  []string{"somethingspecialvalue"},
						"Another-Header": []string{"value"},
					},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RuleHeader{
				Headers:        tt.fields.Headers,
				allowedHeaders: tt.fields.allowedHeaders,
			}
			if err := r.Init(); err != nil {
				t.Errorf("RuleHeader.Init() error = %v", err)
			}

			if got := r.Match(tt.args.req); got != tt.want {
				t.Errorf("RuleHeader.Match() = %v, want %v", got, tt.want)
			}
		})
	}
}
