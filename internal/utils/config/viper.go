package config

import (
	"io/fs"

	"github.com/spf13/viper"
)

func ViperConfigure(path string) (cfg Config, err error) {
	viper.SetConfigName("config")
	viper.AddConfigPath(path)
	if err = viper.ReadInConfig(); err != nil {
		return cfg, err
	}

	if err := viper.Unmarshal(&cfg); err != nil {
		return cfg, err
	}

	viper.SetConfigFile(".env")
	if err = viper.ReadInConfig(); err != nil {
		if _, ok := err.(*fs.PathError); !ok {
			return cfg, err
		}
	}

	if dbPassword := viper.GetString("DB_PASSWORD"); dbPassword != "" {
		cfg.DB.Password = dbPassword
	}

	return cfg, nil
}

type Config struct {
	Api struct {
		Host     string `mapstructure:"host"`
		Port     string `mapstructure:"port"`
		LogLevel string `mapstructure:"logLevel"`
	} `mapstructure:"api"`
	DB struct {
		Host     string `mapstructure:"host"`
		Port     string `mapstructure:"port"`
		DbName   string `mapstructure:"dbName"`
		Username string `mapstructure:"username"`
		Password string `mapstructure:"password"`
		Ssl      bool   `mapstructure:"ssl"`
	} `mapstructure:"db"`
}
