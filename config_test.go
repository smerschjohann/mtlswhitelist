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
			if !reflect.DeepEqual(got.Rules, tt.want.Rules) {
				t.Errorf("NewConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWithExternalData(t *testing.T) {
	// Prepare test: set an environment variable
	key := "TEST"
	value := "127.0.0.1/8,8.8.8.8/32"
	t.Setenv(key, value)

	config := &RawConfig{
		Rules: []RawRule{
			{
				Type: "header",
				Headers: map[string]string{
					"X-Whitelist-Header": "[[ env \"TEST\" ]]",
				},
			},
			{
				Type: "ipRange",
				Ranges: []string{
					"[[ env \"TEST\" ]]",
				},
			},
		},
	}

	got, err := NewConfig(config)
	if err != nil {
		t.Errorf("NewConfig() error = %v", err)
		return
	}

	if got.Rules[0].(*RuleHeader).Headers["X-Whitelist-Header"] != value {
		t.Errorf("NewConfig() = %v, want %v", got.Rules[0].(*RuleHeader).Headers["X-Whitelist-Header"], value)
	}

	ipRanges := got.Rules[1].(*RuleIPRange).Ranges
	if ipRanges[0] != "127.0.0.1/8" {
		t.Errorf("NewConfig() = %v, want %v", ipRanges[0], "127.0.0.1/8")
	}
	if ipRanges[1] != "8.8.8.8/32" {
		t.Errorf("NewConfig() = %v, want %v", ipRanges[0], "8.8.8.8/32")
	}
}

// func TestWithKubernetesResource(t *testing.T) {
// 	// Prepare test: set KTOKEN as environment variable
// 	config := &RawConfig{
// 		Rules: []RawRule{
// 			{
// 				Type: "ipRange",
// 				Ranges: []string{
// 					"[[ .data.ipRange ]]",
// 				},
// 			},
// 		},
// 		ExternalData: ExternalData{
// 			URL: "https://1.2.3.4:6443/api/v1/namespaces/code/configmaps/test",
// 			Headers: map[string]string{
// 				"Content-Type":  "application/json",
// 				"Authorization": "Bearer [[ env \"KTOKEN\" ]]",
// 			},
// 			DataKey:       "data",
// 			SkipTlsVerify: true,
// 		},
// 	}

// 	got, err := NewConfig(config)
// 	if err != nil {
// 		t.Errorf("NewConfig() error = %v", err)
// 		return
// 	}

// 	for _, rule := range got.Rules {
// 		if rule, ok := rule.(*RuleIPRange); ok {
// 			for _, ipRange := range rule.Ranges {
// 				println(ipRange)
// 			}
// 		}
// 	}
// }
