package utils

import "testing"

func TestNormalizeGithubRepo(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"labib0x9/docpine", "https://github.com/labib0x9/docpine.git"},
		{"https://github.com/labib0x9/docpine.git", "https://github.com/labib0x9/docpine.git"},
		{"git@github.com:labib0x9/docpine.git", "https://github.com/labib0x9/docpine.git"},
		{"github.com/labib0x9/docpine", "https://github.com/labib0x9/docpine.git"},
	}
	for _, test := range tests {
		got, ok := NormalizeGithubRepo(test.input)
		if !ok || got != test.want {
			t.Fatalf("NormalizeGithubRepo(%q) = %q, %v; want %q", test.input, got, ok, test.want)
		}
	}
}

func TestNormalizeGithubRepoRejectsInvalid(t *testing.T) {
	inputs := []string{"", "owner", "owner/repo/extra", "owner/../repo", "owner/repo;rm -rf /", "https://example.com/owner/repo"}
	for _, input := range inputs {
		if _, ok := NormalizeGithubRepo(input); ok {
			t.Fatalf("NormalizeGithubRepo(%q) should fail", input)
		}
	}
}
