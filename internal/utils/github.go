package utils

import (
	"strings"
	"unicode"
)

func NormalizeGithubRepo(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	value = strings.TrimSuffix(value, ".git")
	value = strings.TrimPrefix(value, "https://github.com/")
	value = strings.TrimPrefix(value, "http://github.com/")
	value = strings.TrimPrefix(value, "github.com/")
	value = strings.TrimPrefix(value, "git@github.com:")

	parts := strings.Split(value, "/")
	if len(parts) != 2 {
		return "", false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", false
		}
		for _, r := range part {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' && r != '.' {
				return "", false
			}
		}
	}
	return "https://github.com/" + parts[0] + "/" + parts[1] + ".git", true
}
