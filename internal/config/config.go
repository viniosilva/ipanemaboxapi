package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Api   ConfigApi   `mapstructure:"api"`
	MySQL ConfigMySQL `mapstructure:"mysql"`
}

type ConfigApi struct {
	Host string `mapstructure:"host"`
	Port string `mapstructure:"port"`
}

type ConfigMySQL struct {
	Username        string        `mapstructure:"username"`
	Password        string        `mapstructure:"-"`
	Host            string        `mapstructure:"host"`
	Port            string        `mapstructure:"port"`
	Database        string        `mapstructure:"database"`
	ConnMaxLifetime time.Duration `mapstructure:"connMaxLifetime"`
	MaxOpenConns    int           `mapstructure:"maxOpenConns"`
	MaxIdleConns    int           `mapstructure:"maxIdleConns"`
}

func GetConfig(path string) (*Config, error) {
	viper.AddConfigPath(".")

	viper.SetConfigFile(fmt.Sprintf("%s/.env", path))

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	viper.SetConfigFile(fmt.Sprintf("%s/config.yml", path))
	if err := viper.MergeInConfig(); err != nil {
		return nil, err
	}

	var c *Config
	if err := viper.Unmarshal(&c); err != nil {
		return nil, err
	}

	c.MySQL.Password = viper.GetString("MYSQL_PASSWORD")

	return c, nil
}
