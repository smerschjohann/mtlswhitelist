package mtlswhitelist

import (
	"reflect"
	"testing"
)

func TestNewConfig(t *testing.T) {
	type args struct {
		rawConfig *RawConfig
	}
	tests := []struct {
		name    string
		args    args
		want    *Config
		wantErr bool
	}{
		{
			name: "TestNewConfig",
			args: args{
				rawConfig: &RawConfig{
					Rules: []RawRule{
						{
							Type: "allOf",
							Rules: []RawRule{
								{
									Type: "header",
									Headers: map[string]string{
										"X-Whitelist-Header": "true",
									},
								},
							},
						},
					},
				},
			},
			want: &Config{
				Rules: []Rule{
					&RuleAllOf{
						Rules: []Rule{
							&RuleHeader{
								Headers: map[string]string{
									"X-Whitelist-Header": "true",
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewConfig(tt.args.rawConfig)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}
