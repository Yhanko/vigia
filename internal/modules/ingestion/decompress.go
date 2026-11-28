package ingestion

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

const (
	// ADR-017 §3.7 limits.
	MaxCompressedBodyBytes    int64 = 1 << 20  // 1 MiB
	MaxDecompressedBodyBytes  int64 = 10 << 20 // 10 MiB
	MaxEventItemBytes         int64 = 1 << 20  // 1 MiB
	MaxHeaderLineBytes              = 16 << 10 // 16 KiB
	MaxItemsPerEnvelope             = 100
	MaxJSONDepth                    = 64
	MaxNormalizedPayloadBytes       = 256 << 10 // 256 KiB

	zstdMaxDecoderWindow = 8 << 20  // 8 MiB bounded window (ADR-017 §3.8)
	zstdMaxDecoderMemory = 16 << 20 // 16 MiB bounded memory
)

var (
	ErrPayloadTooLarge      = errors.New("ingestion: payload too large")
	ErrUnsupportedEncoding  = errors.New("ingestion: unsupported content-encoding")
	ErrMalformedCompression = errors.New("ingestion: malformed compressed stream")
)

// strictLimitReader reads at most limit bytes; if another byte is available,
// it returns ErrPayloadTooLarge instead of io.EOF.
type strictLimitReader struct {
	r         io.Reader
	remaining int64
}

func (l *strictLimitReader) Read(p []byte) (int, error) {
	if l.remaining <= 0 {
		var probe [1]byte
		n, err := l.r.Read(probe[:])
		if n > 0 {
			return 0, ErrPayloadTooLarge
		}
		if err != nil {
			return 0, err
		}
		return 0, io.EOF
	}
	if int64(len(p)) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.r.Read(p)
	l.remaining -= int64(n)
	return n, err
}

type compositeReadCloser struct {
	io.Reader
	closers []io.Closer
}

func (c *compositeReadCloser) Close() error {
	var firstErr error
	for _, cl := range c.closers {
		if cl == nil {
			continue
		}
		if err := cl.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// DecompressReader wraps body in a streaming decompressor enforcing BOTH
// compressed (1 MiB) and decompressed (10 MiB) byte limits (ADR-017 §3.7-3.8).
// Supported encodings: "", "identity", "gzip", "deflate" (zlib or raw), "br", "zstd".
func DecompressReader(body io.Reader, contentEncoding string, maxCompressed, maxDecompressed int64) (io.ReadCloser, error) {
	if maxCompressed <= 0 {
		maxCompressed = MaxCompressedBodyBytes
	}
	if maxDecompressed <= 0 {
		maxDecompressed = MaxDecompressedBodyBytes
	}

	enc := strings.ToLower(strings.TrimSpace(contentEncoding))
	compLimited := &strictLimitReader{r: body, remaining: maxCompressed}

	var (
		decReader io.Reader
		closers   []io.Closer
	)

	switch enc {
	case "", "identity":
		// For uncompressed requests, compressed limit = 1 MiB applies directly.
		decReader = compLimited
	case "gzip":
		gr, err := gzip.NewReader(compLimited)
		if err != nil {
			if errors.Is(err, ErrPayloadTooLarge) {
				return nil, ErrPayloadTooLarge
			}
			return nil, ErrMalformedCompression
		}
		decReader = gr
		closers = append(closers, gr)
	case "deflate":
		br := bufio.NewReaderSize(compLimited, 4096)
		peek, pErr := br.Peek(2)
		if pErr != nil && len(peek) == 0 {
			if errors.Is(pErr, ErrPayloadTooLarge) {
				return nil, ErrPayloadTooLarge
			}
			return nil, ErrMalformedCompression
		}
		if len(peek) == 2 && isZlibHeader(peek[0], peek[1]) {
			zr, err := zlib.NewReader(br)
			if err != nil {
				return nil, ErrMalformedCompression
			}
			decReader = zr
			closers = append(closers, zr)
		} else {
			fr := flate.NewReader(br)
			decReader = fr
			closers = append(closers, fr)
		}
	case "br":
		decReader = brotli.NewReader(compLimited)
	case "zstd":
		zr, err := zstd.NewReader(compLimited,
			zstd.WithDecoderMaxWindow(zstdMaxDecoderWindow),
			zstd.WithDecoderMaxMemory(zstdMaxDecoderMemory),
			zstd.WithDecoderConcurrency(1),
		)
		if err != nil {
			return nil, ErrMalformedCompression
		}
		decReader = zr
		closers = append(closers, zr.IOReadCloser())
	default:
		return nil, ErrUnsupportedEncoding
	}

	out := &strictLimitReader{r: decReader, remaining: maxDecompressed}
	return &compositeReadCloser{Reader: out, closers: closers}, nil
}

// isZlibHeader checks RFC 1950 CMF/FLG header bytes.
func isZlibHeader(cmf, flg byte) bool {
	if cmf&0x0F != 8 { // deflate method
		return false
	}
	if (cmf >> 4) > 7 { // window size <= 32K
		return false
	}
	return (uint16(cmf)*256+uint16(flg))%31 == 0
}
