#!/usr/bin/env python3
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
INPUT_PATH = os.path.join(ROOT, 'tests', 'router_vectors.yaml')
OUTPUT_PATH = os.path.join(ROOT, 'tests', 'host', 'router_vectors.h')

RESULT_MAP = {
    'OK': 'VHTTP_ROUTER_OK',
    'NOT_FOUND': 'VHTTP_ROUTER_NOT_FOUND',
    'INVALID': 'VHTTP_ROUTER_ERR_INVALID',
    'CONFLICT': 'VHTTP_ROUTER_ERR_CONFLICT',
    'FULL': 'VHTTP_ROUTER_ERR_FULL',
    'UNSUPPORTED': 'VHTTP_ROUTER_ERR_UNSUPPORTED',
    'TOO_LARGE': 'VHTTP_ROUTER_ERR_TOO_LARGE',
}

PARAM_TYPE_MAP = {
    'str': 'VHTTP_PARAM_STR',
    'int': 'VHTTP_PARAM_INT',
    'float': 'VHTTP_PARAM_FLOAT',
    'path': 'VHTTP_PARAM_PATH',
}


def parse_single_quoted(value: str) -> str:
    value = value.strip()
    if not value:
        return value
    if value[0] == "'" and value[-1] == "'":
        inner = value[1:-1]
        return inner.replace("''", "'")
    return value


def parse_int(value: str) -> int:
    return int(value.strip())


def parse_yaml(path: str):
    cases = []
    current = None
    section = None
    current_route = None
    current_query = None
    current_param = None

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
                current = {'name': name, 'routes': [], 'queries': []}
                section = None
                current_route = None
                current_query = None
                current_param = None
                continue

            if current is None:
                continue

            if line.startswith('    routes:'):
                section = 'routes'
                current_route = None
                continue

            if line.startswith('    queries:'):
                section = 'queries'
                current_query = None
                continue

            if section == 'routes':
                if line.startswith('      - method: '):
                    method = parse_single_quoted(line.split(':', 1)[1].strip())
                    current_route = {'method': method}
                    current['routes'].append(current_route)
                    continue

                if line.startswith('        pattern: '):
                    current_route['pattern'] = parse_single_quoted(line.split(':', 1)[1].strip())
                    continue

                if line.startswith('        handler: '):
                    current_route['handler'] = parse_int(line.split(':', 1)[1])
                    continue

                if line.startswith('        add_result: '):
                    current_route['add_result'] = parse_single_quoted(line.split(':', 1)[1].strip())
                    continue

            if section == 'queries':
                if line.startswith('      - method: '):
                    method = parse_single_quoted(line.split(':', 1)[1].strip())
                    current_query = {'method': method, 'expect': {}}
                    current['queries'].append(current_query)
                    continue

                if line.startswith('        path: '):
                    current_query['path'] = parse_single_quoted(line.split(':', 1)[1].strip())
                    continue

                if line.startswith('        expect:'):
                    continue

                if line.startswith('          result: '):
                    current_query['expect']['result'] = parse_single_quoted(line.split(':', 1)[1].strip())
                    continue

                if line.startswith('          handler: '):
                    current_query['expect']['handler'] = parse_int(line.split(':', 1)[1])
                    continue

                if line.startswith('          params: []'):
                    current_query['expect']['params'] = []
                    current_param = None
                    continue

                if line.startswith('          params:'):
                    current_query['expect']['params'] = []
                    current_param = None
                    continue

                if line.startswith('            - name: '):
                    name = parse_single_quoted(line.split(':', 1)[1].strip())
                    current_param = {'name': name}
                    current_query['expect']['params'].append(current_param)
                    continue

                if line.startswith('              value: '):
                    current_param['value'] = parse_single_quoted(line.split(':', 1)[1].strip())
                    continue

                if line.startswith('              type: '):
                    current_param['type'] = parse_single_quoted(line.split(':', 1)[1].strip())
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
    lines.append('// Auto-generated by tools/gen_router_vectors.py. Do not edit directly.')
    lines.append('#pragma once')
    lines.append('')
    lines.append('#include <stddef.h>')
    lines.append('#include <stdint.h>')
    lines.append('#include "vhttp_router.h"')
    lines.append('')
    lines.append('typedef struct {')
    lines.append('    const char *method;')
    lines.append('    const char *pattern;')
    lines.append('    uint16_t handler;')
    lines.append('    vhttp_router_result_t result;')
    lines.append('} vhttp_route_case_t;')
    lines.append('')
    lines.append('typedef struct {')
    lines.append('    const char *name;')
    lines.append('    const char *value;')
    lines.append('    vhttp_param_type_t type;')
    lines.append('} vhttp_expect_param_t;')
    lines.append('')
    lines.append('typedef struct {')
    lines.append('    const char *method;')
    lines.append('    const char *path;')
    lines.append('    vhttp_router_result_t result;')
    lines.append('    uint16_t handler;')
    lines.append('    const vhttp_expect_param_t *params;')
    lines.append('    size_t num_params;')
    lines.append('} vhttp_query_case_t;')
    lines.append('')
    lines.append('typedef struct {')
    lines.append('    const char *name;')
    lines.append('    const vhttp_route_case_t *routes;')
    lines.append('    size_t num_routes;')
    lines.append('    const vhttp_query_case_t *queries;')
    lines.append('    size_t num_queries;')
    lines.append('} vhttp_router_case_t;')
    lines.append('')

    for case in cases:
        cname = case['name']
        routes = case.get('routes', [])
        queries = case.get('queries', [])

        lines.append('static const vhttp_route_case_t routes_%s[] = {' % cname)
        for route in routes:
            result = RESULT_MAP.get(route.get('add_result', 'OK'), 'VHTTP_ROUTER_ERR_INVALID')
            lines.append('    { %s, %s, %d, %s },' % (
                c_escape(route['method']),
                c_escape(route['pattern']),
                int(route['handler']),
                result,
            ))
        lines.append('};')
        lines.append('')

        param_arrays = []
        for qi, query in enumerate(queries):
            params = query.get('expect', {}).get('params', [])
            if params:
                pname = 'params_%s_%d' % (cname, qi)
                param_arrays.append(pname)
                lines.append('static const vhttp_expect_param_t %s[] = {' % pname)
                for param in params:
                    ptype = PARAM_TYPE_MAP.get(param.get('type', 'str'), 'VHTTP_PARAM_STR')
                    lines.append('    { %s, %s, %s },' % (
                        c_escape(param['name']),
                        c_escape(param.get('value', '')),
                        ptype,
                    ))
                lines.append('};')
                lines.append('')
            else:
                param_arrays.append(None)

        lines.append('static const vhttp_query_case_t queries_%s[] = {' % cname)
        for qi, query in enumerate(queries):
            expect = query.get('expect', {})
            result = RESULT_MAP.get(expect.get('result', 'INVALID'), 'VHTTP_ROUTER_ERR_INVALID')
            handler = int(expect.get('handler', 0)) if expect.get('result') == 'OK' else 0
            params = expect.get('params', [])

            if params:
                pname = param_arrays[qi]
                lines.append('    { %s, %s, %s, %d, %s, %d },' % (
                    c_escape(query['method']),
                    c_escape(query['path']),
                    result,
                    handler,
                    pname,
                    len(params),
                ))
            else:
                lines.append('    { %s, %s, %s, %d, NULL, 0 },' % (
                    c_escape(query['method']),
                    c_escape(query['path']),
                    result,
                    handler,
                ))
        lines.append('};')
        lines.append('')

    lines.append('static const vhttp_router_case_t vhttp_router_cases[] = {')
    for case in cases:
        cname = case['name']
        lines.append('    { %s, routes_%s, %d, queries_%s, %d },' % (
            c_escape(cname),
            cname,
            len(case.get('routes', [])),
            cname,
            len(case.get('queries', [])),
        ))
    lines.append('};')
    lines.append('')
    lines.append('static const size_t vhttp_router_case_count = sizeof(vhttp_router_cases) / sizeof(vhttp_router_cases[0]);')
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
