package mtlswhitelist

import (
	"net"
	"net/http"
	"testing"
)

func TestRuleIPRange_Match(t *testing.T) {
	type fields struct {
		Ranges       []string
		AddInterface bool
		allowedCidrs []*net.IPNet
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
			name: "private range match",
			fields: fields{
				Ranges: []string{
					"192.168.100.0/24",
				},
				AddInterface: false,
			},
			args: args{
				req: &http.Request{
					RemoteAddr: "",
					Header: http.Header{
						"X-Real-Ip": []string{"192.168.100.5"},
					},
				},
			},
			want: true,
		},
		{
			name: "public range does not match",
			fields: fields{
				Ranges: []string{
					"192.168.100.0/24",
				},
				AddInterface: false,
			},
			args: args{
				req: &http.Request{
					RemoteAddr: "",
					Header: http.Header{
						"X-Real-Ip": []string{"8.8.8.8"},
					},
				},
			},
			want: false,
		},
		{
			name: "own interface can be added and public ip still not permitted",
			fields: fields{
				AddInterface: true,
			},
			args: args{
				req: &http.Request{
					RemoteAddr: "",
					Header: http.Header{
						"X-Real-Ip": []string{"8.8.8.8"},
					},
				},
			},
			want: false,
		},
		{
			name: "own interface can be added and private ip in range allowed",
			fields: fields{
				AddInterface: true,
			},
			args: args{
				req: &http.Request{
					RemoteAddr: "",
					Header: http.Header{
						"X-Real-Ip": []string{"192.168.0.10"},
					},
				},
			},
			want: true,
		},

		{
			name: "own interface can be added and private ip not in range not allowed",
			fields: fields{
				AddInterface: true,
			},
			args: args{
				req: &http.Request{
					RemoteAddr: "",
					Header: http.Header{
						"X-Real-Ip": []string{"10.10.0.10"},
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RuleIPRange{
				Ranges:       tt.fields.Ranges,
				AddInterface: tt.fields.AddInterface,
			}
			if err := r.Init(); err != nil {
				t.Errorf("RuleIPRange.Init() error = %v", err)
			}

			if got := r.Match(tt.args.req); got != tt.want {
				t.Errorf("RuleIPRange.Match() = %v, want %v", got, tt.want)
			}
		})
	}
}
