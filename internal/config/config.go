package config

import (
	"errors"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"
)

type Abuse struct {
	TurnstileSecret string
}

type Logger struct {
	Directory  string
	Filename   string
	MaxSize    int
	MaxBackups int
	MaxAge     int
	Compress   bool
	Format     string
	Level      string
}

type OAuthGithub struct {
	ClientID           string
	ClientSecret       string
	CallbackURL        string
	TokenURL           string
	UserURL            string
	SessionSecret      []byte
	ForceSecure        bool
	GithubAuthorizeURL string
}

type Database struct {
	DSN string
}

type RabbitMQ struct {
	URL            string
	Queue          string
	EventsExchange string
}

type Lab struct {
	Image       string
	Timeout     time.Duration
	MemoryLimit int64
	CPUShares   int64
}

type Config struct {
	Version        string
	Addr           string
	Port           int
	Service        string
	Abuse          *Abuse
	Logger         *Logger
	Database       *Database
	RabbitMQ       *RabbitMQ
	Lab            *Lab
	OAuthGithub    *OAuthGithub
	AllowedOrigins []string
}

var (
	configuration *Config
	once          sync.Once
)

func loadConfig() {
	viper.SetConfigFile(".env")
	if err := viper.ReadInConfig(); err != nil {
		if !os.IsNotExist(err) && !errors.As(err, &viper.ConfigFileNotFoundError{}) {
			var pathErr *os.PathError
			if !errors.As(err, &pathErr) {
				log.Panic(err)
			}
		}
	}

	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// defaults for optional values
	viper.SetDefault("VERSION", "1.0.0")
	viper.SetDefault("SERVICE_NAME", "docpine")
	viper.SetDefault("ADDR", "0.0.0.0")
	viper.SetDefault("PORT", 8080)
	viper.SetDefault("LOG_DIR", "")
	viper.SetDefault("LOG_FILE", "")
	viper.SetDefault("LOG_MAX_SIZE", 100)
	viper.SetDefault("LOG_MAX_BACKUPS", 5)
	viper.SetDefault("LOG_MAX_AGE", 28)
	viper.SetDefault("LOG_COMPRESS", true)
	viper.SetDefault("LOG_FORMAT", "text")
	viper.SetDefault("LOG_LEVEL", "info")
	viper.SetDefault("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/docpine?sslmode=disable")
	viper.SetDefault("RABBITMQ_URL", "amqp://docpine:docpine@localhost:5672/")
	viper.SetDefault("RABBITMQ_QUEUE", "docpine.lab.runs")
	viper.SetDefault("RABBITMQ_EVENTS_EXCHANGE", "docpine.lab.events")
	viper.SetDefault("LAB_RUNNER_IMAGE", "alpine:3.20")
	viper.SetDefault("LAB_RUN_TIMEOUT", "10m")
	viper.SetDefault("LAB_MEMORY", int64(256*1024*1024))
	viper.SetDefault("LAB_CPU_SHARES", int64(0))
	viper.SetDefault("GITHUB_AUTHORIZE_URL", "https://github.com/login/oauth/authorize")
	viper.SetDefault("GITHUB_TOKEN_URL", "https://github.com/login/oauth/access_token")
	viper.SetDefault("GITHUB_USER_URL", "https://api.github.com/user")

	required := func(key string) string {
		val := viper.GetString(key)
		if val == "" {
			log.Panic(key)
		}
		return val
	}

	cookieSecret := []byte(required("COOKIE_SECRET"))

	origins := viper.GetString("ALLOWED_ORIGINS")
	allowedOrigins := make([]string, 0, 10)

	for _, origin := range strings.Split(origins, ",") {
		if trimmed := strings.TrimSpace(origin); trimmed != "" {
			allowedOrigins = append(allowedOrigins, trimmed)
		}
	}

	configuration = &Config{
		Version: required("VERSION"),
		Addr:    viper.GetString("ADDR"),
		Port:    viper.GetInt("PORT"),
		Service: required("SERVICE_NAME"),
		Abuse: &Abuse{
			TurnstileSecret: viper.GetString("TURNSTILE_SECRET"),
		},
		Logger: &Logger{
			Directory:  viper.GetString("LOG_DIR"),
			Filename:   viper.GetString("LOG_FILE"),
			MaxSize:    viper.GetInt("LOG_MAX_SIZE"),
			MaxBackups: viper.GetInt("LOG_MAX_BACKUPS"),
			MaxAge:     viper.GetInt("LOG_MAX_AGE"),
			Compress:   viper.GetBool("LOG_COMPRESS"),
			Format:     viper.GetString("LOG_FORMAT"),
			Level:      viper.GetString("LOG_LEVEL"),
		},
		Database: &Database{
			DSN: viper.GetString("DATABASE_URL"),
		},
		RabbitMQ: &RabbitMQ{
			URL:            viper.GetString("RABBITMQ_URL"),
			Queue:          viper.GetString("RABBITMQ_QUEUE"),
			EventsExchange: viper.GetString("RABBITMQ_EVENTS_EXCHANGE"),
		},
		Lab: &Lab{
			Image:       viper.GetString("LAB_RUNNER_IMAGE"),
			Timeout:     viper.GetDuration("LAB_RUN_TIMEOUT"),
			MemoryLimit: viper.GetInt64("LAB_MEMORY"),
			CPUShares:   viper.GetInt64("LAB_CPU_SHARES"),
		},
		OAuthGithub: &OAuthGithub{
			ClientID:           viper.GetString("GITHUB_CLIENT_ID"),
			ClientSecret:       viper.GetString("GITHUB_CLIENT_SECRET"),
			CallbackURL:        viper.GetString("GITHUB_CALLBACK_URL"),
			TokenURL:           viper.GetString("GITHUB_TOKEN_URL"),
			UserURL:            viper.GetString("GITHUB_USER_URL"),
			SessionSecret:      cookieSecret,
			ForceSecure:        viper.GetBool("GITHUB_FORCE_SECURE"),
			GithubAuthorizeURL: viper.GetString("GITHUB_AUTHORIZE_URL"),
		},
		AllowedOrigins: allowedOrigins,
	}
}

func GetConfig() *Config {
	once.Do(func() {
		loadConfig()
	})
	return configuration
}
