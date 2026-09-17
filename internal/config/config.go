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

type Runtime struct {
	Name           string
	Image          string
	NetworkMode    string
	MemoryLimit    int64
	CPUShares      int64
	RunscPath      string
	FirecrackerBin string
	KernelPath     string
	RootFSPath     string
}

type Abuse struct {
	TurnstileSecret string
	CookieSecret    []byte
	RateBurst       int
	RateRefillRate  time.Duration
}

type Session struct {
	TTL           time.Duration
	MaxConcurrent int
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

type Config struct {
	Version        string
	Addr           string
	Port           int
	Service        string
	Runtime        *Runtime
	Session        *Session
	Abuse          *Abuse
	Logger         *Logger
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
	viper.SetDefault("RUNTIME_NAME", "docker")
	viper.SetDefault("IMAGE", "alpine:3.20")
	viper.SetDefault("NETWORK_MODE", "none")
	viper.SetDefault("SANDBOX_MEMORY", int64(128*1024*1024))
	viper.SetDefault("CPU_SHARES", int64(0))
	viper.SetDefault("RUNSC_PATH", "runsc")
	viper.SetDefault("FIRECRACKER_BIN", "firecracker")
	viper.SetDefault("KERNEL_PATH", "/var/lib/docpine/vmlinux")
	viper.SetDefault("ROOTFS_PATH", "/var/lib/docpine/rootfs.ext4")
	viper.SetDefault("SESSION_TTL", "5m")
	viper.SetDefault("MAX_SESSIONS", 20)
	viper.SetDefault("RATE_LIMIT_BURST", 5)
	viper.SetDefault("RATE_LIMIT_REFILL", "30s")
	viper.SetDefault("LOG_DIR", "")
	viper.SetDefault("LOG_FILE", "")
	viper.SetDefault("LOG_MAX_SIZE", 100)
	viper.SetDefault("LOG_MAX_BACKUPS", 5)
	viper.SetDefault("LOG_MAX_AGE", 28)
	viper.SetDefault("LOG_COMPRESS", true)
	viper.SetDefault("LOG_FORMAT", "text")
	viper.SetDefault("LOG_LEVEL", "info")

	required := func(key string) string {
		val := viper.GetString(key)
		if val == "" {
			log.Panic(key)
		}
		return val
	}

	cookieSecret := []byte(required("COOKIE_SECRET"))

	sessionTTL := viper.GetDuration("SESSION_TTL")
	rateRefill := viper.GetDuration("RATE_LIMIT_REFILL")

	configuration = &Config{
		Version: required("VERSION"),
		Addr:    viper.GetString("ADDR"),
		Port:    viper.GetInt("PORT"),
		Service: required("SERVICE_NAME"),
		Runtime: &Runtime{
			Name:           required("RUNTIME_NAME"),
			Image:          required("IMAGE"),
			NetworkMode:    viper.GetString("NETWORK_MODE"),
			MemoryLimit:    viper.GetInt64("SANDBOX_MEMORY"),
			CPUShares:      viper.GetInt64("CPU_SHARES"),
			RunscPath:      viper.GetString("RUNSC_PATH"),
			FirecrackerBin: viper.GetString("FIRECRACKER_BIN"),
			KernelPath:     viper.GetString("KERNEL_PATH"),
			RootFSPath:     viper.GetString("ROOTFS_PATH"),
		},
		Session: &Session{
			TTL:           sessionTTL,
			MaxConcurrent: viper.GetInt("MAX_SESSIONS"),
		},
		Abuse: &Abuse{
			TurnstileSecret: required("TURNSTILE_SECRET"),
			CookieSecret:    cookieSecret,
			RateBurst:       viper.GetInt("RATE_LIMIT_BURST"),
			RateRefillRate:  rateRefill,
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
		AllowedOrigins: viper.GetStringSlice("ALLOWED_ORIGINS"),
	}
}

func GetConfig() *Config {
	once.Do(func() {
		loadConfig()
	})
	return configuration
}
