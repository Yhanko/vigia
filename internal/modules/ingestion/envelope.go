package ingestion

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

var (
	ErrMalformedEnvelope = errors.New("ingestion: malformed sentry envelope")
	ErrTooManyItems      = errors.New("ingestion: envelope exceeds maximum item count")
	ErrHeaderTooLarge    = errors.New("ingestion: envelope header line exceeds limit")
	ErrJSONTooDeep       = errors.New("ingestion: json nesting exceeds maximum depth")
)

// EnvelopeHeader is the first JSON line of a Sentry envelope (ADR-017 §3.4).
type EnvelopeHeader struct {
	EventID string `json:"event_id"`
	DSN     string `json:"dsn"`
	SentAt  string `json:"sent_at"`
	SDK     *struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"sdk"`
}

// ItemHeader is the JSON header line preceding each envelope item.
type ItemHeader struct {
	Type        string `json:"type"`
	Length      *int64 `json:"length"`
	ContentType string `json:"content_type"`
	Filename    string `json:"filename"`
}

// EnvelopeResult holds the parsed envelope header, extracted `event` payloads,
// and counts of dropped non-event items for metrics (ADR-017 §3.5).
type EnvelopeResult struct {
	Header       EnvelopeHeader
	Events       [][]byte
	DroppedItems map[string]int
	TotalItems   int
}

// ParseEnvelope parses a Sentry envelope stream without buffering non-event
// items in memory, enforcing all ADR-017 §3.4 and §3.7 limits.
func ParseEnvelope(r io.Reader) (EnvelopeResult, error) {
	br := bufio.NewReaderSize(r, 16*1024)

	headerLine, err := readBoundedLine(br, MaxHeaderLineBytes)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return EnvelopeResult{}, ErrMalformedEnvelope
		}
		return EnvelopeResult{}, err
	}
	headerLine = bytes.TrimSpace(headerLine)
	if len(headerLine) == 0 {
		return EnvelopeResult{}, ErrMalformedEnvelope
	}
	if err := CheckJSONDepth(headerLine, MaxJSONDepth); err != nil {
		return EnvelopeResult{}, err
	}
	var envHeader EnvelopeHeader
	if err := json.Unmarshal(headerLine, &envHeader); err != nil {
		return EnvelopeResult{}, ErrMalformedEnvelope
	}

	res := EnvelopeResult{
		Header:       envHeader,
		DroppedItems: make(map[string]int),
	}

	oversizedEvents := 0

	for {
		line, lErr := readBoundedLine(br, MaxHeaderLineBytes)
		if errors.Is(lErr, io.EOF) {
			break
		}
		if lErr != nil {
			return EnvelopeResult{}, lErr
		}
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			// Skip trailing/empty newlines between items.
			continue
		}

		res.TotalItems++
		if res.TotalItems > MaxItemsPerEnvelope {
			return EnvelopeResult{}, ErrTooManyItems
		}
		if err := CheckJSONDepth(trimmed, MaxJSONDepth); err != nil {
			return EnvelopeResult{}, err
		}

		var itemHdr ItemHeader
		if err := json.Unmarshal(trimmed, &itemHdr); err != nil {
			return EnvelopeResult{}, ErrMalformedEnvelope
		}
		itemType := strings.TrimSpace(itemHdr.Type)
		if itemType == "" {
			return EnvelopeResult{}, ErrMalformedEnvelope
		}

		if itemHdr.Length != nil {
			length := *itemHdr.Length
			if length < 0 {
				return EnvelopeResult{}, ErrMalformedEnvelope
			}
			if itemType == "event" && length <= MaxEventItemBytes {
				payload := make([]byte, length)
				if _, err := io.ReadFull(br, payload); err != nil {
					if errors.Is(err, ErrPayloadTooLarge) {
						return EnvelopeResult{}, ErrPayloadTooLarge
					}
					// Lying length: fewer bytes than declared (ADR-017 §3.4).
					return EnvelopeResult{}, ErrMalformedEnvelope
				}
				if err := consumeExpectedNewlineOrEOF(br); err != nil {
					return EnvelopeResult{}, err
				}
				res.Events = append(res.Events, payload)
			} else {
				// Skip in streaming without buffering (either non-event item or oversized event).
				n, cErr := io.CopyN(io.Discard, br, length)
				if cErr != nil {
					if errors.Is(cErr, ErrPayloadTooLarge) {
						return EnvelopeResult{}, ErrPayloadTooLarge
					}
					return EnvelopeResult{}, ErrMalformedEnvelope
				}
				if n != length {
					return EnvelopeResult{}, ErrMalformedEnvelope
				}
				if err := consumeExpectedNewlineOrEOF(br); err != nil {
					return EnvelopeResult{}, err
				}
				if itemType == "event" {
					oversizedEvents++
				} else {
					res.DroppedItems[itemType]++
				}
			}
		} else {
			// No length declared: payload runs until next '\n' or EOF.
			if itemType == "event" {
				payload, oversized, pErr := readLineUpToLimit(br, MaxEventItemBytes)
				if pErr != nil {
					return EnvelopeResult{}, pErr
				}
				if oversized {
					oversizedEvents++
				} else {
					res.Events = append(res.Events, payload)
				}
			} else {
				if err := discardUntilNewlineOrEOF(br); err != nil {
					return EnvelopeResult{}, err
				}
				res.DroppedItems[itemType]++
			}
		}
	}

	// ADR-017 §3.7: if an event item exceeded 1 MiB and it was the sole item, return 413.
	if oversizedEvents > 0 && res.TotalItems == oversizedEvents {
		return EnvelopeResult{}, ErrPayloadTooLarge
	}

	return res, nil
}

// CheckJSONDepth verifies that JSON nesting depth (arrays/objects) does not
// exceed maxDepth (ADR-017 §3.7: 64 levels).
func CheckJSONDepth(data []byte, maxDepth int) error {
	depth := 0
	inString := false
	escaped := false

	for _, b := range data {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if b == '\\' {
				escaped = true
				continue
			}
			if b == '"' {
				inString = false
			}
			continue
		}
		switch b {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > maxDepth {
				return ErrJSONTooDeep
			}
		case '}', ']':
			if depth > 0 {
				depth--
			}
		}
	}
	return nil
}

func readBoundedLine(br *bufio.Reader, maxLen int) ([]byte, error) {
	var out []byte
	for {
		frag, err := br.ReadSlice('\n')
		if len(out)+len(frag) > maxLen {
			return nil, ErrHeaderTooLarge
		}
		out = append(out, frag...)
		if err == nil {
			// Trim trailing \r\n or \n.
			out = bytes.TrimRight(out, "\r\n")
			return out, nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) {
			if len(out) == 0 {
				return nil, io.EOF
			}
			out = bytes.TrimRight(out, "\r\n")
			return out, nil
		}
		return nil, err
	}
}

func consumeExpectedNewlineOrEOF(br *bufio.Reader) error {
	b, err := br.ReadByte()
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	if b == '\n' {
		return nil
	}
	if b == '\r' {
		next, nErr := br.ReadByte()
		if errors.Is(nErr, io.EOF) || (nErr == nil && next == '\n') {
			return nil
		}
		return ErrMalformedEnvelope
	}
	// Lying length: non-newline byte immediately after declared payload length.
	return ErrMalformedEnvelope
}

func readLineUpToLimit(br *bufio.Reader, limit int64) ([]byte, bool, error) {
	var out []byte
	oversized := false
	for {
		frag, err := br.ReadSlice('\n')
		if !oversized {
			if int64(len(out)+len(frag)) > limit+2 { // allow \r\n
				oversized = true
				out = nil
			} else {
				out = append(out, frag...)
			}
		}
		if err == nil {
			if !oversized {
				out = bytes.TrimRight(out, "\r\n")
				if int64(len(out)) > limit {
					return nil, true, nil
				}
			}
			return out, oversized, nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) {
			if !oversized {
				out = bytes.TrimRight(out, "\r\n")
				if int64(len(out)) > limit {
					return nil, true, nil
				}
			}
			return out, oversized, nil
		}
		return nil, false, err
	}
}

func discardUntilNewlineOrEOF(br *bufio.Reader) error {
	for {
		_, err := br.ReadSlice('\n')
		if err == nil || errors.Is(err, io.EOF) {
			return nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return err
	}
}
