#!/usr/bin/env python3
import os
import sys
import codecs

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
INPUT_PATH = os.path.join(ROOT, 'tests', 'parser_vectors.yaml')
OUTPUT_PATH = os.path.join(ROOT, 'tests', 'host', 'parser_vectors.h')

RESULT_MAP = {
    'OK': 'VHTTP_PARSE_OK',
    'INCOMPLETE': 'VHTTP_PARSE_INCOMPLETE',
    'INVALID': 'VHTTP_PARSE_INVALID',
    'TOO_LARGE': 'VHTTP_PARSE_TOO_LARGE',
    'UNSUPPORTED': 'VHTTP_PARSE_UNSUPPORTED',
}


def parse_single_quoted(value: str) -> str:
    value = value.strip()
    if not value:
        return value
    if value[0] == "'" and value[-1] == "'":
        inner = value[1:-1]
        return inner.replace("''", "'")
    return value


def unescape_c(s: str) -> str:
    return codecs.decode(s, 'unicode_escape')


def parse_int(value: str) -> int:
    return int(value.strip())


def parse_yaml(path: str):
    cases = []
    current = None
    section = None
    last_item = None

    with open(path, 'r', encoding='ascii') as f:
        for raw_line in f:
            line = raw_line.rstrip('\n')
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue

            if line.startswith('cases:'):
                continue

            if line.startswith('  - name: '):
                if current is not None:
                    cases.append(current)
                name = parse_single_quoted(line.split(':', 1)[1].strip())
                current = {'name': name, 'expect': {}}
                section = None
                last_item = None
                continue

            if current is None:
                continue

            if line.startswith('    raw: '):
                raw_val = parse_single_quoted(line.split(':', 1)[1].strip())
                current['raw'] = unescape_c(raw_val)
                continue

            if line.startswith('    expect:'):
                section = 'expect'
                last_item = None
                continue

            if line.startswith('      result: '):
                current['expect']['result'] = line.split(':', 1)[1].strip()
                continue

            if line.startswith('      method: '):
                current['expect']['method'] = parse_single_quoted(line.split(':', 1)[1].strip())
                continue

            if line.startswith('      uri: '):
                current['expect']['uri'] = parse_single_quoted(line.split(':', 1)[1].strip())
                continue

            if line.startswith('      path: '):
                current['expect']['path'] = parse_single_quoted(line.split(':', 1)[1].strip())
                continue

            if line.startswith('      query: '):
                current['expect']['query'] = parse_single_quoted(line.split(':', 1)[1].strip())
                continue

            if line.startswith('      headers: []'):
                current['expect']['headers'] = []
                section = None
                last_item = None
                continue

            if line.startswith('      headers:'):
                current['expect']['headers'] = []
                section = 'headers'
                last_item = None
                continue

            if line.startswith('      query_params: []'):
                current['expect']['query_params'] = []
                section = None
                last_item = None
                continue

            if line.startswith('      query_params:'):
                current['expect']['query_params'] = []
                section = 'query_params'
                last_item = None
                continue

            if line.startswith('      content_length: '):
                current['expect']['content_length'] = parse_int(line.split(':', 1)[1])
                continue

            if line.startswith('      is_chunked: '):
                current['expect']['is_chunked'] = parse_int(line.split(':', 1)[1])
                continue

            if line.startswith('      is_websocket: '):
                current['expect']['is_websocket'] = parse_int(line.split(':', 1)[1])
                continue

            if line.startswith('      body: '):
                current['expect']['body'] = parse_single_quoted(line.split(':', 1)[1].strip())
                continue

            if line.startswith('        - name: '):
                if section == 'headers':
                    name = parse_single_quoted(line.split(':', 1)[1].strip())
                    item = {'name': name}
                    current['expect']['headers'].append(item)
                    last_item = item
                continue

            if line.startswith('        - key: '):
                if section == 'query_params':
                    key = parse_single_quoted(line.split(':', 1)[1].strip())
                    item = {'key': key}
                    current['expect']['query_params'].append(item)
                    last_item = item
                continue

            if line.startswith('          value: '):
                if last_item is not None:
                    last_item['value'] = parse_single_quoted(line.split(':', 1)[1].strip())
                continue

            if line.startswith('          has_value: '):
                if last_item is not None:
                    last_item['has_value'] = parse_int(line.split(':', 1)[1])
                continue

    if current is not None:
        cases.append(current)

    return cases


def c_escape(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if ch == '\\':
            out.append('\\\\')
        elif ch == '"':
            out.append('\\"')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif ch == '\t':
            out.append('\\t')
        elif 32 <= o <= 126:
            out.append(ch)
        else:
            out.append('\\x%02x' % o)
    return '"' + ''.join(out) + '"'


def emit_header(cases, out_path):
    lines = []
    lines.append('// Auto-generated by tools/gen_parser_vectors.py. Do not edit directly.')
    lines.append('#pragma once')
    lines.append('')
    lines.append('#include <stddef.h>')
    lines.append('#include <stdint.h>')
    lines.append('#include "vhttp_parser.h"')
    lines.append('')
    lines.append('typedef struct {')
    lines.append('    const char *name;')
    lines.append('    const char *value;')
    lines.append('} vhttp_expect_header_t;')
    lines.append('')
    lines.append('typedef struct {')
    lines.append('    const char *key;')
    lines.append('    const char *value;')
    lines.append('    uint8_t has_value;')
    lines.append('} vhttp_expect_query_t;')
    lines.append('')
    lines.append('typedef struct {')
    lines.append('    const char *name;')
    lines.append('    const char *raw;')
    lines.append('    size_t raw_len;')
    lines.append('    vhttp_parse_result_t result;')
    lines.append('    const char *method;')
    lines.append('    const char *uri;')
    lines.append('    const char *path;')
    lines.append('    const char *query;')
    lines.append('    const vhttp_expect_header_t *headers;')
    lines.append('    size_t num_headers;')
    lines.append('    const vhttp_expect_query_t *query_params;')
    lines.append('    size_t num_query_params;')
    lines.append('    uint32_t content_length;')
    lines.append('    uint8_t is_chunked;')
    lines.append('    uint8_t is_websocket;')
    lines.append('    const char *body;')
    lines.append('    size_t body_len;')
    lines.append('} vhttp_test_case_t;')
    lines.append('')

    for case in cases:
        name = case['name']
        expect = case.get('expect', {})
        result = expect.get('result', 'INVALID')

        headers = expect.get('headers', []) if result == 'OK' else []
        query_params = expect.get('query_params', []) if result == 'OK' else []

        if headers:
            lines.append('static const vhttp_expect_header_t headers_%s[] = {' % name)
            for h in headers:
                lines.append('    { %s, %s },' % (c_escape(h['name']), c_escape(h.get('value', ''))))
            lines.append('};')

        if query_params:
            lines.append('static const vhttp_expect_query_t query_%s[] = {' % name)
            for qp in query_params:
                lines.append('    { %s, %s, %d },' % (
                    c_escape(qp['key']),
                    c_escape(qp.get('value', '')),
                    int(qp.get('has_value', 0))
                ))
            lines.append('};')
        lines.append('')

    lines.append('static const vhttp_test_case_t vhttp_test_cases[] = {')
    for case in cases:
        name = case['name']
        raw = case.get('raw', '')
        expect = case.get('expect', {})
        result = expect.get('result', 'INVALID')

        result_enum = RESULT_MAP.get(result, 'VHTTP_PARSE_INVALID')

        method = expect.get('method', '') if result == 'OK' else ''
        uri = expect.get('uri', '') if result == 'OK' else ''
        path = expect.get('path', '') if result == 'OK' else ''
        query = expect.get('query', '') if result == 'OK' else ''
        body = expect.get('body', '') if result == 'OK' else ''

        headers = expect.get('headers', []) if result == 'OK' else []
        query_params = expect.get('query_params', []) if result == 'OK' else []

        content_length = expect.get('content_length', 0) if result == 'OK' else 0
        is_chunked = expect.get('is_chunked', 0) if result == 'OK' else 0
        is_websocket = expect.get('is_websocket', 0) if result == 'OK' else 0

        raw_len = len(raw)
        body_len = len(body)

        lines.append('    {')
        lines.append('        %s,' % c_escape(name))
        lines.append('        %s,' % c_escape(raw))
        lines.append('        %d,' % raw_len)
        lines.append('        %s,' % result_enum)
        lines.append('        %s,' % c_escape(method))
        lines.append('        %s,' % c_escape(uri))
        lines.append('        %s,' % c_escape(path))
        lines.append('        %s,' % c_escape(query))

        if headers:
            lines.append('        headers_%s,' % name)
            lines.append('        %d,' % len(headers))
        else:
            lines.append('        NULL,')
            lines.append('        0,')

        if query_params:
            lines.append('        query_%s,' % name)
            lines.append('        %d,' % len(query_params))
        else:
            lines.append('        NULL,')
            lines.append('        0,')

        lines.append('        %d,' % content_length)
        lines.append('        %d,' % is_chunked)
        lines.append('        %d,' % is_websocket)
        lines.append('        %s,' % c_escape(body))
        lines.append('        %d,' % body_len)
        lines.append('    },')

    lines.append('};')
    lines.append('')
    lines.append('static const size_t vhttp_test_case_count = sizeof(vhttp_test_cases) / sizeof(vhttp_test_cases[0]);')
    lines.append('')

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w', encoding='ascii', newline='\n') as f:
        f.write('\n'.join(lines) + '\n')


def main():
    if not os.path.exists(INPUT_PATH):
        print('Missing input: %s' % INPUT_PATH, file=sys.stderr)
        return 1

    cases = parse_yaml(INPUT_PATH)
    if not cases:
        print('No cases found in %s' % INPUT_PATH, file=sys.stderr)
        return 1

    emit_header(cases, OUTPUT_PATH)
    print('Wrote %s (%d cases)' % (OUTPUT_PATH, len(cases)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
