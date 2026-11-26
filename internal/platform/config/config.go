// Package config lê e valida a configuração da aplicação a partir de variáveis de ambiente.
package config

import (
	"fmt"
	"os"
	"strconv"
)

// Config contém a configuração do processo.
type Config struct {
	// Port é a porta HTTP onde a API escuta (variável PORT; por defeito 8080).
	Port int
}

// Load lê a configuração do ambiente e falha cedo se algum valor for inválido.
func Load() (Config, error) {
	cfg := Config{Port: 8080}

	if v := os.Getenv("PORT"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p < 1 || p > 65535 {
			return Config{}, fmt.Errorf("PORT inválida %q: tem de ser um número entre 1 e 65535", v)
		}
		cfg.Port = p
	}

	return cfg, nil
}
