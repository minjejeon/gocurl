package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ameshkov/gocurl/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfig_DataMultiple(t *testing.T) {
	args := []string{
		"-d", "a=1",
		"-d", "b=2",
		"http://example.com",
	}

	cfg, err := config.ParseConfig(args)
	require.NoError(t, err)
	assert.Equal(t, "a=1&b=2", cfg.Data)
}

func TestParseConfig_DataURLEncode(t *testing.T) {
	testCases := []struct {
		name     string
		args     []string
		expected string
	}{
		{
			name:     "simple_name_content",
			args:     []string{"--data-urlencode", "param=hello world", "http://example.com"},
			expected: "param=hello+world",
		},
		{
			name:     "multiple_data_urlencode",
			args:     []string{"--data-urlencode", "a=1 2", "--data-urlencode", "b=3&4", "http://example.com"},
			expected: "a=1+2&b=3%264",
		},
		{
			name:     "content_only",
			args:     []string{"--data-urlencode", "hello world", "http://example.com"},
			expected: "hello+world",
		},
		{
			name:     "starts_with_equal",
			args:     []string{"--data-urlencode", "=hello world", "http://example.com"},
			expected: "hello+world",
		},
		{
			name:     "name_content_with_at",
			args:     []string{"--data-urlencode", "email=user@example.com", "http://example.com"},
			expected: "email=user%40example.com",
		},
		{
			name: "mixed_with_data_preserving_order",
			args: []string{
				"-d", "first=1",
				"--data-urlencode", "second=a b",
				"-d", "third=3",
				"http://example.com",
			},
			expected: "first=1&second=a+b&third=3",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.ParseConfig(tc.args)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, cfg.Data)
		})
	}
}

func TestParseConfig_DataURLEncode_Files(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "test.txt")
	err := os.WriteFile(filePath, []byte("file content & spaces\n"), 0o600)
	require.NoError(t, err)

	t.Run("at_file", func(t *testing.T) {
		args := []string{"--data-urlencode", "@" + filePath, "http://example.com"}
		cfg, err := config.ParseConfig(args)
		require.NoError(t, err)
		assert.Equal(t, "file+content+%26+spaces%0A", cfg.Data)
	})

	t.Run("name_at_file", func(t *testing.T) {
		args := []string{"--data-urlencode", "data@" + filePath, "http://example.com"}
		cfg, err := config.ParseConfig(args)
		require.NoError(t, err)
		assert.Equal(t, "data=file+content+%26+spaces%0A", cfg.Data)
	})
}

func TestParseConfig_Data_Files(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "test.txt")
	err := os.WriteFile(filePath, []byte("file data\r\nline 2\n"), 0o600)
	require.NoError(t, err)

	args := []string{"-d", "@" + filePath, "http://example.com"}
	cfg, err := config.ParseConfig(args)
	require.NoError(t, err)
	assert.Equal(t, "file dataline 2", cfg.Data)
}

func TestParseConfig_Data_Errors(t *testing.T) {
	t.Run("nonexistent_file_data", func(t *testing.T) {
		args := []string{"-d", "@/nonexistent/path/file.txt", "http://example.com"}
		_, err := config.ParseConfig(args)
		require.Error(t, err)
	})

	t.Run("nonexistent_file_data_urlencode", func(t *testing.T) {
		args := []string{"--data-urlencode", "@/nonexistent/path/file.txt", "http://example.com"}
		_, err := config.ParseConfig(args)
		require.Error(t, err)
	})

	t.Run("nonexistent_name_at_file", func(t *testing.T) {
		args := []string{"--data-urlencode", "key@/nonexistent/path/file.txt", "http://example.com"}
		_, err := config.ParseConfig(args)
		require.Error(t, err)
	})
}
