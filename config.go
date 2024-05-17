package mtlswhitelist

import (
	"fmt"
	"net/http"
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
	Match(*http.Request) bool
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
	Rules []Rule `json:"rules"`
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

func mapRules(rawRules []RawRule) ([]Rule, error) {
	var rules []Rule = make([]Rule, 0)
	for _, rawRule := range rawRules {
		println("Mapping rule: ", rawRule.Type)
		var rule Rule
		switch rawRule.Type {
		case AllOf:
			rrule := &RuleAllOf{}
			rules, err := mapRules(rawRule.Rules)
			if err != nil {
				return nil, fmt.Errorf("error mapping rules: %w", err)
			}
			rrule.Rules = rules
			rule = rrule
		case AnyOf:
			rrule := &RuleAnyOf{}
			rules, err := mapRules(rawRule.Rules)
			if err != nil {
				return nil, fmt.Errorf("error mapping rules: %w", err)
			}
			rrule.Rules = rules
			rule = rrule
		case NoneOf:
			rrule := &RuleNoneOf{}
			rules, err := mapRules(rawRule.Rules)
			if err != nil {
				return nil, fmt.Errorf("error mapping rules: %w", err)
			}
			rrule.Rules = rules
			rule = rrule
		case IPRange:
			rrule := &RuleIPRange{}
			rrule.Ranges = rawRule.Ranges
			rrule.AddInterface = rawRule.AddInterface
			rule = rrule
		case Header:
			rrule := &RuleHeader{}
			rrule.Headers = rawRule.Headers
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

	rules, err := mapRules(rawConfig.Rules)
	if err != nil {
		return nil, err
	}
	config.Rules = rules
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
