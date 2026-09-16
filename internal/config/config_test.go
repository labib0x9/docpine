package config

// func TestConfig_LoadDefaults(t *testing.T) {
// 	cfg := GetConfig()

// 	if cfg.Addr != "0.0.0.0" {
// 		t.Fatalf("expected default addr 0.0.0.0, got %s", cfg.Addr)
// 	}
// 	if cfg.Port != 8080 {
// 		t.Fatalf("expected default port 8080, got %d", cfg.Port)
// 	}
// 	if cfg.Service != "docpine" {
// 		t.Fatalf("expected default service docpine, got %s", cfg.Service)
// 	}
// 	if cfg.Runtime.Name != "docker" {
// 		t.Fatalf("expected default runtime 'docker', got %s", cfg.Runtime.Name)
// 	}
// 	if cfg.Session.TTL != 5*time.Minute {
// 		t.Fatalf("expected default TTL 5m, got %v", cfg.Session.TTL)
// 	}
// 	if cfg.Session.MaxConcurrent != 20 {
// 		t.Fatalf("expected default max concurrent 20, got %d", cfg.Session.MaxConcurrent)
// 	}
// 	if cfg.Abuse.PoWDifficulty != 16 {
// 		t.Fatalf("expected default PoW difficulty 16, got %d", cfg.Abuse.PoWDifficulty)
// 	}
// 	if len(cfg.Abuse.CookieSecret) == 0 {
// 		t.Fatal("expected auto-generated cookie secret")
// 	}
// 	if cfg.Runtime.Image != "alpine:3.20" {
// 		t.Fatalf("expected default image alpine:3.20, got %s", cfg.Runtime.Image)
// 	}
// 	if cfg.Runtime.MemoryLimit != 128*1024*1024 {
// 		t.Fatalf("expected default memory limit 128MB, got %d", cfg.Runtime.MemoryLimit)
// 	}
// 	if cfg.Sensor.Port != 8081 {
// 		t.Fatalf("expected sensor port 8081, got %d", cfg.Sensor.Port)
// 	}
// }

// func TestConfig_ToGuardConfig(t *testing.T) {
// 	cfg := GetConfig()
// 	guardCfg := cfg.ToGuardConfig()

// 	if guardCfg.PoWDifficulty != cfg.Abuse.PoWDifficulty {
// 		t.Fatalf("expected PoWDifficulty %d, got %d", cfg.Abuse.PoWDifficulty, guardCfg.PoWDifficulty)
// 	}
// 	if guardCfg.MaxConcurrent != cfg.Session.MaxConcurrent {
// 		t.Fatalf("expected MaxConcurrent %d, got %d", cfg.Session.MaxConcurrent, guardCfg.MaxConcurrent)
// 	}
// }

// func TestConfig_ToRuntimeConfig(t *testing.T) {
// 	cfg := GetConfig()
// 	rtCfg := cfg.Runtime.ToRuntimeConfig()

// 	if rtCfg.Image != cfg.Runtime.Image {
// 		t.Fatalf("expected image %s, got %s", cfg.Runtime.Image, rtCfg.Image)
// 	}
// 	if rtCfg.MemoryLimit != cfg.Runtime.MemoryLimit {
// 		t.Fatalf("expected memory limit %d, got %d", cfg.Runtime.MemoryLimit, rtCfg.MemoryLimit)
// 	}
// }

// func TestConfig_Singleton(t *testing.T) {
// 	c1 := GetConfig()
// 	c2 := GetConfig()
// 	if c1 != c2 {
// 		t.Fatalf("expected GetConfig() to return identical pointer singleton, got %p vs %p", c1, c2)
// 	}
// }
