# ViperHTTP HTTP Parser Contract (Phase 1)

This contract defines the zero-copy HTTP/1.1 request parser used by the Core 0 C server.
It is the source of truth for parsing behavior and host-side tests.

## Scope
- Parse HTTP/1.1 request line, headers, and optional body.
- Split the request target into path + query string.
- Split query into key/value pairs (no percent decoding).
- Detect Content-Length, Transfer-Encoding: chunked, and Upgrade: websocket.
- Never allocate on the hot path and never modify the input buffer.

## Non-Goals (Phase 1)
- Chunked transfer decoding.
- Percent decoding or UTF-8 normalization.
- Header folding / multiline headers.
- HTTP/2, HTTP/1.0 downgrade behavior.

## Limits (from vhttp_config.h)
- VHTTP_MAX_HEADERS = 24
- VHTTP_MAX_URI_LEN = 512
- VHTTP_MAX_HEADER_SIZE = 4096
- VHTTP_MAX_BODY_SIZE = 65536
- VHTTP_MAX_PATH_PARAMS = 8
- VHTTP_MAX_QUERY_PARAMS = 16 (new, to be added)

## Data Types

```
typedef struct {
    const char *ptr;
    uint16_t    len;
} vhttp_slice_t;

typedef struct {
    vhttp_slice_t key;
    vhttp_slice_t value;
    uint8_t       has_value;
} vhttp_kv_t;

typedef struct {
    const char *name;
    uint8_t     name_len;
    const char *value;
    uint16_t    value_len;
} vhttp_header_t;

typedef struct {
    vhttp_slice_t method;
    vhttp_slice_t uri;        // raw target from request line
    vhttp_slice_t path;       // uri split before '?'
    vhttp_slice_t query;      // uri split after '?', without '?'

    vhttp_header_t headers[VHTTP_MAX_HEADERS];
    uint8_t        num_headers;

    vhttp_kv_t     query_params[VHTTP_MAX_QUERY_PARAMS];
    uint8_t        num_query_params;

    const char    *body;
    uint32_t       body_len;

    uint32_t       content_length;   // 0 if absent
    uint8_t        is_chunked;       // Transfer-Encoding: chunked
    uint8_t        is_websocket;     // Upgrade: websocket
} vhttp_parsed_request_t;

typedef enum {
    VHTTP_PARSE_OK = 0,
    VHTTP_PARSE_INCOMPLETE,
    VHTTP_PARSE_INVALID,
    VHTTP_PARSE_TOO_LARGE,
    VHTTP_PARSE_UNSUPPORTED
} vhttp_parse_result_t;
```

## Function Signature

```
vhttp_parse_result_t vhttp_parse_request(
    const char *buf,
    size_t len,
    vhttp_parsed_request_t *out
);
```

## Parsing Rules
1. Require CRLF for line endings in request line and headers.
2. Request line format: "METHOD SP TARGET SP HTTP/1.1".
3. METHOD, TARGET, and VERSION must be non-empty.
4. TARGET length must not exceed VHTTP_MAX_URI_LEN.
5. Header lines are "Name: value". Name cannot be empty.
6. Total headers (count) must not exceed VHTTP_MAX_HEADERS.
7. Total header bytes must not exceed VHTTP_MAX_HEADER_SIZE.
8. Header name matching is case-insensitive for feature detection.
9. If Content-Length is present:
   - parse as base-10 integer
   - if > VHTTP_MAX_BODY_SIZE -> VHTTP_PARSE_TOO_LARGE
   - if body not fully present -> VHTTP_PARSE_INCOMPLETE
10. If Transfer-Encoding: chunked is present -> VHTTP_PARSE_UNSUPPORTED
    (until Phase 3).
11. If Upgrade: websocket is present (case-insensitive) -> is_websocket = 1.
12. Query params parsing:
   - Split on '&' into key/value pairs.
   - Key-only pairs are allowed (has_value = 0).
   - No percent decoding, no '+' to space conversion.
   - If params exceed VHTTP_MAX_QUERY_PARAMS -> VHTTP_PARSE_TOO_LARGE.

## Output Guarantees
- All slices point into the original buffer.
- No heap allocations during parsing.
- On VHTTP_PARSE_OK, `out` fields are valid and bounded.
- On non-OK results, `out` may be partially filled and must be treated as invalid.
