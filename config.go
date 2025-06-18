package mtlswhitelist

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	AllOf   string = "allOf"
	AnyOf   string = "anyOf"
	NoneOf  string = "noneOf"
	IPRange string = "ipRange"
	Header  string = "header"
)

type Rule interface {
	Init() error
	Match(req *http.Request) bool
}

type BaseRule struct {
	Type string `json:"type"`
}

type RuleAllOf struct {
	Rules []Rule `json:"rules"`
}

type RuleAnyOf struct {
	Rules []Rule `json:"rules"`
}

type RuleNoneOf struct {
	Rules []Rule `json:"rules"`
}

type Config struct {
	CreationTime  time.Time
	NextUpdate    *time.Time
	Rules         []Rule `json:"rules"`
	RejectMessage string
	RejectCode    int
}

func (r *RuleAllOf) Init() error {
	for _, rule := range r.Rules {
		err := rule.Init()
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *RuleAllOf) Match(req *http.Request) bool {
	for _, rule := range r.Rules {
		if !rule.Match(req) {
			return false
		}
	}
	return true
}

func (r *RuleAnyOf) Init() error {
	for _, rule := range r.Rules {
		err := rule.Init()
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *RuleAnyOf) Match(req *http.Request) bool {
	for _, rule := range r.Rules {
		if rule.Match(req) {
			return true
		}
	}
	return false
}

func (r *RuleNoneOf) Init() error {
	for _, rule := range r.Rules {
		err := rule.Init()
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *RuleNoneOf) Match(req *http.Request) bool {
	for _, rule := range r.Rules {
		if rule.Match(req) {
			return false
		}
	}
	return true
}

//nolint:gocognit,gocyclo,funlen
func mapRules(tmplData map[string]interface{}, rawRules []RawRule) ([]Rule, error) {
	rules := make([]Rule, 0, len(rawRules))
	for _, rawRule := range rawRules {
		var rule Rule
		switch rawRule.Type {
		case AllOf:
			rrule := &RuleAllOf{}
			allOfRules, err := mapRules(tmplData, rawRule.Rules)
			if err != nil {
				return nil, fmt.Errorf("error mapping rules: %w", err)
			}
			rrule.Rules = allOfRules
			rule = rrule
		case AnyOf:
			rrule := &RuleAnyOf{}
			anyOfRules, err := mapRules(tmplData, rawRule.Rules)
			if err != nil {
				return nil, fmt.Errorf("error mapping rules: %w", err)
			}
			rrule.Rules = anyOfRules
			rule = rrule
		case NoneOf:
			rrule := &RuleNoneOf{}
			noneOfRules, err := mapRules(tmplData, rawRule.Rules)
			if err != nil {
				return nil, fmt.Errorf("error mapping rules: %w", err)
			}
			rrule.Rules = noneOfRules
			rule = rrule
		case IPRange:
			rrule := &RuleIPRange{}
			for _, rangeStr := range rawRule.Ranges {
				val, err := templateValue(rangeStr, tmplData)
				if err != nil {
					return nil, fmt.Errorf("error templating value: %w", err)
				}
				if strings.Contains(val, ",") {
					ranges := strings.Split(val, ",")
					for _, rangeStr := range ranges {
						rangeStr = strings.TrimSpace(rangeStr)
						if rangeStr != "" {
							rrule.Ranges = append(rrule.Ranges, rangeStr)
						}
					}
				} else {
					rangeStr = strings.TrimSpace(val)
					if rangeStr != "" {
						rrule.Ranges = append(rrule.Ranges, rangeStr)
					}
				}
			}
			rrule.AddInterface = rawRule.AddInterface
			rule = rrule
		case Header:
			rrule := &RuleHeader{}
			rrule.Headers = make(map[string]string, len(rawRule.Headers))
			for key, value := range rawRule.Headers {
				val, err := templateValue(value, tmplData)
				if err != nil {
					return nil, fmt.Errorf("error templating value: %w", err)
				}
				rrule.Headers[key] = val
			}
			rule = rrule
		default:
			return nil, fmt.Errorf("unknown rule type: %s", rawRule.Type)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func NewConfig(rawConfig *RawConfig) (*Config, error) {
	config := &Config{}
	tmplData := make(map[string]interface{})

	if rawConfig.ExternalData.URL != "" {
		data, err := GetExternalData(rawConfig.ExternalData)
		if err != nil {
			return nil, err
		}
		tmplData["data"] = data[rawConfig.ExternalData.DataKey]
	}
	fmt.Printf("external data: %v\n", tmplData)

	rules, err := mapRules(tmplData, rawConfig.Rules)
	if err != nil {
		return nil, err
	}
	config.CreationTime = time.Now()
	config.Rules = rules

	if rawConfig.RefreshInterval != "" {
		duration, err := time.ParseDuration(rawConfig.RefreshInterval)
		if err != nil {
			return nil, fmt.Errorf("error parsing refresh interval: %w", err)
		}
		nextUpdate := config.CreationTime.Add(duration)
		config.NextUpdate = &nextUpdate
	} else {
		config.NextUpdate = nil
	}

	if rawConfig.RejectMessage != nil {
		config.RejectMessage = rawConfig.RejectMessage.Message
		config.RejectCode = rawConfig.RejectMessage.Code
	} else {
		config.RejectMessage = "Forbidden"
	}

	if config.RejectCode <= 0 {
		config.RejectCode = 403
	}

	return config, nil
}

func (c *Config) Init() error {
	for _, rule := range c.Rules {
		err := rule.Init()
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) Match(req *http.Request) bool {
	for _, rule := range c.Rules {
		if rule.Match(req) {
			return true
		}
	}
	return false
}
