package ripple

import (
	"gitlab.com/flarenetwork/coreth/flare"
)

var DefaultConfig = Config{
	Currency: flare.CurrencyRipple,
}

type Config struct {
	Currency string
}

type Option func(*Config)

func WithCurrency(currency string) func(*Config) {
	return func(cfg *Config) {
		cfg.Currency = currency
	}
}