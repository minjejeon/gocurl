package config

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
)

// dataEntry represents a single data chunk specified on the command line.
type dataEntry struct {
	value       string
	isURLEncode bool
}

// processData processes both -d/--data and --data-urlencode arguments,
// preserving their command-line order and combining them with '&'.
func processData(args []string, opts *Options) (data string, err error) {
	entries := parseDataEntries(args)
	if len(entries) == 0 {
		for _, d := range opts.Data {
			entries = append(entries, dataEntry{value: d, isURLEncode: false})
		}
		for _, d := range opts.DataURLEncode {
			entries = append(entries, dataEntry{value: d, isURLEncode: true})
		}
	}

	if len(entries) == 0 {
		return "", nil
	}

	parts := make([]string, 0, len(entries))
	for _, entry := range entries {
		var part string
		if entry.isURLEncode {
			part, err = encodeURLEntry(entry.value)
		} else {
			part, err = processRawData(entry.value)
		}
		if err != nil {
			return "", err
		}
		parts = append(parts, part)
	}

	return strings.Join(parts, "&"), nil
}

// parseDataEntries scans args to find -d/--data and --data-urlencode arguments
// in their exact command-line order.
func parseDataEntries(args []string) (entries []dataEntry) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}

		if arg == "-d" || arg == "--data" {
			if i+1 < len(args) {
				entries = append(entries, dataEntry{value: args[i+1], isURLEncode: false})
				i++
			}
		} else if strings.HasPrefix(arg, "-d") && len(arg) > 2 {
			entries = append(entries, dataEntry{value: arg[2:], isURLEncode: false})
		} else if strings.HasPrefix(arg, "--data=") {
			entries = append(entries, dataEntry{value: strings.TrimPrefix(arg, "--data="), isURLEncode: false})
		} else if arg == "--data-urlencode" {
			if i+1 < len(args) {
				entries = append(entries, dataEntry{value: args[i+1], isURLEncode: true})
				i++
			}
		} else if strings.HasPrefix(arg, "--data-urlencode=") {
			entries = append(entries, dataEntry{value: strings.TrimPrefix(arg, "--data-urlencode="), isURLEncode: true})
		}
	}

	return entries
}

// encodeURLEntry encodes a single --data-urlencode argument according to curl rules:
//   - @filename: read file and URL-encode its content
//   - =content: URL-encode content, omit leading '='
//   - name=content: URL-encode content only, keep name=
//   - name@filename: read file and URL-encode its content, prepend name=
//   - content: URL-encode whole content
func encodeURLEntry(val string) (string, error) {
	if strings.HasPrefix(val, "@") {
		content, err := readDataFile(val[1:])
		if err != nil {
			return "", err
		}

		return url.QueryEscape(content), nil
	}

	if strings.HasPrefix(val, "=") {
		return url.QueryEscape(val[1:]), nil
	}

	eqIdx := strings.Index(val, "=")
	atIdx := strings.Index(val, "@")

	if eqIdx != -1 && (atIdx == -1 || eqIdx < atIdx) {
		name := val[:eqIdx]
		content := val[eqIdx+1:]

		return name + "=" + url.QueryEscape(content), nil
	}

	if atIdx != -1 {
		name := val[:atIdx]
		filename := val[atIdx+1:]
		content, err := readDataFile(filename)
		if err != nil {
			return "", err
		}

		return name + "=" + url.QueryEscape(content), nil
	}

	return url.QueryEscape(val), nil
}

// processRawData processes a -d/--data argument. If it starts with '@', it reads
// from the specified file and strips carriage returns and newlines.
func processRawData(val string) (string, error) {
	if strings.HasPrefix(val, "@") {
		content, err := readDataFile(val[1:])
		if err != nil {
			return "", err
		}

		content = strings.ReplaceAll(content, "\r", "")
		content = strings.ReplaceAll(content, "\n", "")

		return content, nil
	}

	return val, nil
}

// readDataFile reads content from a file or from stdin if filename is "-".
func readDataFile(filename string) (string, error) {
	if filename == "-" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("failed to read from stdin: %w", err)
		}

		return string(b), nil
	}

	b, err := os.ReadFile(filename)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", filename, err)
	}

	return string(b), nil
}
