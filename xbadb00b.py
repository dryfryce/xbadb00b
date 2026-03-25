#!/usr/bin/env python3
"""
XBADB00B — QuickJS Bytecode Decompiler
Supports: Frida v2, Bellard v1/v5, QuickJS-NG v24, big-endian variants

Format:
  [u8 version] [leb128 atom_count] [atoms...] [u8 BC_TAG] [function...]
"""

import sys, struct
from dataclasses import dataclass, field
from typing import List, Tuple, Optional

# ─── Frida QuickJS Opcode Table (0-indexed, from frida/quickjs quickjs-opcode.h) ───
# DEF entries only (not def/temporary). Numbering = line order - 1.
FRIDA_OPS = [
    # 0x00
    ("invalid", 1, "none"),
    ("push_i32", 5, "i32"),
    ("push_const", 5, "const"),
    ("fclosure", 5, "const"),
    ("push_atom_value", 5, "atom"),
    ("private_symbol", 5, "atom"),
    ("undefined", 1, "none"),
    ("null", 1, "none"),
    # 0x08
    ("push_this", 1, "none"),
    ("push_false", 1, "none"),
    ("push_true", 1, "none"),
    ("object", 1, "none"),
    ("special_object", 2, "u8"),
    ("rest", 3, "u16"),
    ("drop", 1, "none"),
    ("nip", 1, "none"),
    # 0x10
    ("nip1", 1, "none"),
    ("dup", 1, "none"),
    ("dup1", 1, "none"),
    ("dup2", 1, "none"),
    ("dup3", 1, "none"),
    ("insert2", 1, "none"),
    ("insert3", 1, "none"),
    ("insert4", 1, "none"),
    # 0x18
    ("perm3", 1, "none"),
    ("perm4", 1, "none"),
    ("perm5", 1, "none"),
    ("swap", 1, "none"),
    ("swap2", 1, "none"),
    ("rot3l", 1, "none"),
    ("rot3r", 1, "none"),
    ("rot4l", 1, "none"),
    # 0x20
    ("rot5l", 1, "none"),
    ("call_constructor", 3, "npop"),
    ("call", 3, "npop"),
    ("tail_call", 3, "npop"),
    ("call_method", 3, "npop"),
    ("tail_call_method", 3, "npop"),
    ("array_from", 3, "npop"),
    ("apply", 3, "u16"),
    # 0x28
    ("return", 1, "none"),
    ("return_undef", 1, "none"),
    ("check_ctor_return", 1, "none"),
    ("check_ctor", 1, "none"),
    ("check_brand", 1, "none"),
    ("add_brand", 1, "none"),
    ("return_async", 1, "none"),
    ("throw", 1, "none"),
    # 0x30
    ("throw_error", 6, "atom_u8"),
    ("eval", 5, "npop_u16"),
    ("apply_eval", 3, "u16"),
    ("regexp", 1, "none"),
    ("get_super", 1, "none"),
    ("import", 1, "none"),
    ("check_var", 5, "atom"),
    ("get_var_undef", 5, "atom"),
    # 0x38
    ("get_var", 5, "atom"),
    ("put_var", 5, "atom"),
    ("put_var_init", 5, "atom"),
    ("put_var_strict", 5, "atom"),
    ("get_ref_value", 1, "none"),
    ("put_ref_value", 1, "none"),
    ("define_var", 6, "atom_u8"),
    ("check_define_var", 6, "atom_u8"),
    # 0x40
    ("define_func", 6, "atom_u8"),
    ("get_field", 5, "atom"),
    ("get_field2", 5, "atom"),
    ("put_field", 5, "atom"),
    ("get_private_field", 1, "none"),
    ("put_private_field", 1, "none"),
    ("define_private_field", 1, "none"),
    ("get_array_el", 1, "none"),
    # 0x48
    ("get_array_el2", 1, "none"),
    ("put_array_el", 1, "none"),
    ("get_super_value", 1, "none"),
    ("put_super_value", 1, "none"),
    ("define_field", 5, "atom"),
    ("set_name", 5, "atom"),
    ("set_name_computed", 1, "none"),
    ("set_proto", 1, "none"),
    # 0x50
    ("set_home_object", 1, "none"),
    ("define_array_el", 1, "none"),
    ("append", 1, "none"),
    ("copy_data_properties", 2, "u8"),
    ("define_method", 6, "atom_u8"),
    ("define_method_computed", 2, "u8"),
    ("define_class", 6, "atom_u8"),
    ("define_class_computed", 6, "atom_u8"),
    # 0x58
    ("get_loc", 3, "u16"),
    ("put_loc", 3, "u16"),
    ("set_loc", 3, "u16"),
    ("get_arg", 3, "u16"),
    ("put_arg", 3, "u16"),
    ("set_arg", 3, "u16"),
    ("get_var_ref", 3, "u16"),
    ("put_var_ref", 3, "u16"),
    # 0x60
    ("set_var_ref", 3, "u16"),
    ("set_loc_uninitialized", 3, "u16"),
    ("get_loc_check", 3, "u16"),
    ("put_loc_check", 3, "u16"),
    ("put_loc_check_init", 3, "u16"),
    ("get_loc_checkthis", 3, "u16"),
    ("get_var_ref_check", 3, "u16"),
    ("put_var_ref_check", 3, "u16"),
    # 0x68
    ("put_var_ref_check_init", 3, "u16"),
    ("close_loc", 3, "u16"),
    ("if_false", 5, "label"),
    ("if_true", 5, "label"),
    ("goto", 5, "label"),
    ("catch", 5, "label"),
    ("gosub", 5, "label"),
    ("ret", 1, "none"),
    # 0x70
    ("nip_catch", 1, "none"),
    ("to_object", 1, "none"),
    ("to_propkey", 1, "none"),
    ("to_propkey2", 1, "none"),
    ("with_get_var", 10, "atom_label_u8"),
    ("with_put_var", 10, "atom_label_u8"),
    ("with_delete_var", 10, "atom_label_u8"),
    ("with_make_ref", 10, "atom_label_u8"),
    # 0x78
    ("with_get_ref", 10, "atom_label_u8"),
    ("with_get_ref_undef", 10, "atom_label_u8"),
    ("make_loc_ref", 7, "atom_u16"),
    ("make_arg_ref", 7, "atom_u16"),
    ("make_var_ref_ref", 7, "atom_u16"),
    ("make_var_ref", 5, "atom"),
    ("for_in_start", 1, "none"),
    ("for_of_start", 1, "none"),
    # 0x80
    ("for_await_of_start", 1, "none"),
    ("for_in_next", 1, "none"),
    ("for_of_next", 2, "u8"),
    ("iterator_check_object", 1, "none"),
    ("iterator_get_value_done", 1, "none"),
    ("iterator_close", 1, "none"),
    ("iterator_next", 1, "none"),
    ("iterator_call", 2, "u8"),
    # 0x88
    ("initial_yield", 1, "none"),
    ("yield", 1, "none"),
    ("yield_star", 1, "none"),
    ("async_yield_star", 1, "none"),
    ("await", 1, "none"),
    ("neg", 1, "none"),
    ("plus", 1, "none"),
    ("dec", 1, "none"),
    # 0x90
    ("inc", 1, "none"),
    ("post_dec", 1, "none"),
    ("post_inc", 1, "none"),
    ("dec_loc", 2, "u8"),
    ("inc_loc", 2, "u8"),
    ("add_loc", 2, "u8"),
    ("not", 1, "none"),
    ("lnot", 1, "none"),
    # 0x98
    ("typeof", 1, "none"),
    ("delete", 1, "none"),
    ("delete_var", 5, "atom"),
    ("mul", 1, "none"),
    ("div", 1, "none"),
    ("mod", 1, "none"),
    ("add", 1, "none"),
    ("sub", 1, "none"),
    # 0xa0
    ("pow", 1, "none"),
    ("shl", 1, "none"),
    ("sar", 1, "none"),
    ("shr", 1, "none"),
    ("lt", 1, "none"),
    ("lte", 1, "none"),
    ("gt", 1, "none"),
    ("gte", 1, "none"),
    # 0xa8
    ("instanceof", 1, "none"),
    ("in", 1, "none"),
    ("eq", 1, "none"),
    ("neq", 1, "none"),
    ("strict_eq", 1, "none"),
    ("strict_neq", 1, "none"),
    ("and", 1, "none"),
    ("xor", 1, "none"),
    # 0xb0
    ("or", 1, "none"),
    ("is_undefined_or_null", 1, "none"),
    ("private_in", 1, "none"),
    ("mul_pow10", 1, "none"),  # CONFIG_BIGNUM
    ("math_mod", 1, "none"),   # CONFIG_BIGNUM
    ("nop", 1, "none"),
    # Short opcodes (after temps are skipped, these are the actual emitted ones)
    # 0xb6
    ("push_minus1", 1, "none"),
    ("push_0", 1, "none"),
    ("push_1", 1, "none"),
    ("push_2", 1, "none"),
    ("push_3", 1, "none"),
    ("push_4", 1, "none"),
    ("push_5", 1, "none"),
    ("push_6", 1, "none"),
    ("push_7", 1, "none"),
    ("push_i8", 2, "i8"),
    # 0xc0
    ("push_i16", 3, "i16"),
    ("push_const8", 2, "u8"),
    ("fclosure8", 2, "u8"),
    ("push_empty_string", 1, "none"),
    ("get_loc8", 2, "u8"),
    ("put_loc8", 2, "u8"),
    ("set_loc8", 2, "u8"),
    ("get_loc0", 1, "none"),
    # 0xc8
    ("get_loc1", 1, "none"),
    ("get_loc2", 1, "none"),
    ("get_loc3", 1, "none"),
    ("put_loc0", 1, "none"),
    ("put_loc1", 1, "none"),
    ("put_loc2", 1, "none"),
    ("put_loc3", 1, "none"),
    ("set_loc0", 1, "none"),
    # 0xd0
    ("set_loc1", 1, "none"),
    ("set_loc2", 1, "none"),
    ("set_loc3", 1, "none"),
    ("get_arg0", 1, "none"),
    ("get_arg1", 1, "none"),
    ("get_arg2", 1, "none"),
    ("get_arg3", 1, "none"),
    ("put_arg0", 1, "none"),
    # 0xd8
    ("put_arg1", 1, "none"),
    ("put_arg2", 1, "none"),
    ("put_arg3", 1, "none"),
    ("set_arg0", 1, "none"),
    ("set_arg1", 1, "none"),
    ("set_arg2", 1, "none"),
    ("set_arg3", 1, "none"),
    ("get_var_ref0", 1, "none"),
    # 0xe0
    ("get_var_ref1", 1, "none"),
    ("get_var_ref2", 1, "none"),
    ("get_var_ref3", 1, "none"),
    ("put_var_ref0", 1, "none"),
    ("put_var_ref1", 1, "none"),
    ("put_var_ref2", 1, "none"),
    ("put_var_ref3", 1, "none"),
    ("set_var_ref0", 1, "none"),
    # 0xe8
    ("set_var_ref1", 1, "none"),
    ("set_var_ref2", 1, "none"),
    ("set_var_ref3", 1, "none"),
    ("get_length", 1, "none"),
    ("if_false8", 2, "label8"),
    ("if_true8", 2, "label8"),
    ("goto8", 2, "label8"),
    ("goto16", 3, "label16"),
    # 0xf0
    ("call0", 1, "none"),
    ("call1", 1, "none"),
    ("call2", 1, "none"),
    ("call3", 1, "none"),
    ("is_undefined", 1, "none"),
    ("is_null", 1, "none"),
    ("typeof_is_undefined", 1, "none"),
    ("typeof_is_function", 1, "none"),
]

OP_MAP = {i: op for i, op in enumerate(FRIDA_OPS)}


def read_leb128(data, pos):
    result = 0; shift = 0
    while pos < len(data):
        b = data[pos]; pos += 1
        result |= (b & 0x7f) << shift
        if not (b & 0x80): break
        shift += 7
    return result, pos


FIRST_ATOM = 228
BUILTINS = ['<null>', 'null', 'false', 'true', 'if', 'else', 'return', 'var', 'this', 'delete', 'void', 'typeof', 'new', 'in', 'instanceof', 'do', 'while', 'for', 'break', 'continue', 'switch', 'case', 'default', 'throw', 'try', 'catch', 'finally', 'function', 'debugger', 'with', 'class', 'const', 'enum', 'export', 'extends', 'import', 'super', 'implements', 'interface', 'let', 'package', 'private', 'protected', 'public', 'static', 'yield', 'await', '', 'length', 'fileName', 'lineNumber', 'message', 'cause', 'errors', 'stack', 'prepareStackTrace', 'name', 'toString', 'toLocaleString', 'valueOf', 'eval', 'prototype', 'constructor', 'configurable', 'writable', 'enumerable', 'value', 'get', 'set', 'of', '__proto__', 'undefined', 'number', 'boolean', 'string', 'object', 'symbol', 'integer', 'unknown', 'arguments', 'callee', 'caller', '<eval>', '<ret>', '<var>', '<arg_var>', '<with>', 'lastIndex', 'target', 'index', 'input', 'defineProperties', 'apply', 'join', 'concat', 'split', 'construct', 'getPrototypeOf', 'setPrototypeOf', 'isExtensible', 'preventExtensions', 'has', 'deleteProperty', 'defineProperty', 'getOwnPropertyDescriptor', 'ownKeys', 'add', 'done', 'next', 'values', 'source', 'flags', 'global', 'unicode', 'raw', 'new.target', 'this.active_func', '<home_object>', '<computed_field>', '<static_computed_field>', '<class_fields_init>', '<brand>', '#constructor', 'as', 'from', 'meta', '*default*', '*', 'Module', 'then', 'resolve', 'reject', 'promise', 'proxy', 'revoke', 'async', 'exec', 'groups', 'indices', 'status', 'reason', 'globalThis', 'bigint', 'bigfloat', 'bigdecimal', 'roundingMode', 'maximumSignificantDigits', 'maximumFractionDigits', 'not-equal', 'timed-out', 'ok', 'toJSON', 'Object', 'Array', 'Error', 'Number', 'String', 'Boolean', 'Symbol', 'Arguments', 'Math', 'JSON', 'Date', 'Function', 'GeneratorFunction', 'ForInIterator', 'RegExp', 'ArrayBuffer', 'SharedArrayBuffer', 'Uint8ClampedArray', 'Int8Array', 'Uint8Array', 'Int16Array', 'Uint16Array', 'Int32Array', 'Uint32Array', 'BigInt64Array', 'BigUint64Array', 'Float32Array', 'Float64Array', 'DataView', 'BigInt', 'BigFloat', 'BigFloatEnv', 'BigDecimal', 'OperatorSet', 'Operators', 'Map', 'Set', 'WeakMap', 'WeakSet', 'Map Iterator', 'Set Iterator', 'Array Iterator', 'String Iterator', 'RegExp String Iterator', 'Generator', 'Proxy', 'Promise', 'PromiseResolveFunction', 'PromiseRejectFunction', 'AsyncFunction', 'AsyncFunctionResolve', 'AsyncFunctionReject', 'AsyncGeneratorFunction', 'AsyncGenerator', 'EvalError', 'RangeError', 'ReferenceError', 'SyntaxError', 'TypeError', 'URIError', 'InternalError', '<brand>', 'Symbol.toPrimitive', 'Symbol.iterator', 'Symbol.match', 'Symbol.matchAll', 'Symbol.replace', 'Symbol.search', 'Symbol.split', 'Symbol.toStringTag', 'Symbol.isConcatSpreadable', 'Symbol.hasInstance', 'Symbol.species', 'Symbol.unscopables', 'Symbol.asyncIterator', 'Symbol.operatorSet']

def resolve_bc_atom_leb(atoms, raw_leb):
    """Resolve atom from LEB128-encoded value in function headers (bc_put_atom/bc_get_atom).
    bc_get_atom: read leb v; if v&1 → tagged int(v>>1); else → bc_idx_to_atom(v>>1)
    bc_idx_to_atom: if idx < FIRST_ATOM → builtin; else → idx_to_atom[idx - FIRST_ATOM]"""
    if raw_leb & 1:
        # Tagged integer (numeric property name)
        return str(raw_leb >> 1)
    else:
        idx = raw_leb >> 1
        if idx < FIRST_ATOM:
            # Builtin atom
            if idx < len(BUILTINS):
                return BUILTINS[idx]
            return f"<builtin_{idx}>"
        else:
            # Custom atom from file's atom table
            custom_idx = idx - FIRST_ATOM
            if custom_idx < len(atoms):
                return atoms[custom_idx]
            return f"<custom_{custom_idx}>"

def resolve_bc_atom(atoms, raw_u32):
    """Resolve atom from u32 in bytecode operands.
    bc_atom_to_idx: builtins (< FIRST_ATOM) stored as-is, 
    custom stored as (sequential_idx + FIRST_ATOM)"""
    if raw_u32 < FIRST_ATOM:
        # Builtin atom
        if raw_u32 < len(BUILTINS):
            return BUILTINS[raw_u32]
        return f"<builtin_{raw_u32}>"
    else:
        # Custom atom: index = raw - FIRST_ATOM
        idx = raw_u32 - FIRST_ATOM
        if idx < len(atoms):
            return atoms[idx]
        return f"<custom_{idx}>"


def parse_file(data):
    """Parse QuickJS bytecode file — auto-detects version"""
    # ── Version detection ──
    try:
        from version_tables import get_version_config, VERSION_REGISTRY
        vcfg = get_version_config(data[0]) if data else None
    except ImportError:
        vcfg = None

    # Override atom resolution if we have version config
    if vcfg is not None:
        global FIRST_ATOM, BUILTINS, resolve_bc_atom, resolve_bc_atom_leb
        _vcfg = vcfg
        FIRST_ATOM = vcfg.first_atom
        BUILTINS = vcfg.atom_table

        def resolve_bc_atom(atoms, raw_u32):
            return _vcfg.resolve_atom(atoms, raw_u32)

        def resolve_bc_atom_leb(atoms, raw_leb):
            return _vcfg.resolve_atom_leb(atoms, raw_leb)

        # Update opcode lookup
        global OP_MAP
        OP_MAP = vcfg.opcode_table

    pos = 0
    out = []

    # ─── Atom table ───
    version = data[pos]; pos += 1
    atom_count, pos = read_leb128(data, pos)

    version_names = {1: 'Bellard v1 (no BigNum)', 2: 'Frida v2 (CONFIG_BIGNUM)',
                     5: 'Bellard v5 (upstream current)', 24: 'QuickJS-NG v24',
                     0x41: 'Bellard v1 BE', 0x42: 'Frida v2 BE', 0x45: 'Bellard v5 BE'}
    vname = version_names.get(version, f'Unknown v{version}')
    out.append(f"BC_VERSION: {version} ({vname})")
    out.append(f"Atom count: {atom_count}\n")

    atoms = []
    for i in range(atom_count):
        enc, pos = read_leb128(data, pos)
        slen = enc >> 1
        is_wide = enc & 1
        if is_wide:
            name = ''.join(chr(data[pos+j*2] | (data[pos+j*2+1]<<8)) for j in range(slen))
            pos += slen * 2
        else:
            name = data[pos:pos+slen].decode('ascii', errors='replace')
            pos += slen
        atoms.append(name)
        out.append(f'  [{i:2d}] "{name}"')

    out.append(f"\nAtom table ends @ 0x{pos:03x}")

    # ─── Function(s) ───
    func_num = 0
    parsed_functions = []
    current_parent = None
    bc_tag_func = vcfg.bc_tag_func if vcfg else 0x0E
    while pos < len(data):
        tag = data[pos]
        if tag != bc_tag_func:
            out.append(f"\nUnexpected tag 0x{tag:02x} @ 0x{pos:03x}, stopping")
            break
        pos += 1

        out.append(f"\n{'='*60}")
        out.append(f"FUNCTION #{func_num} @ 0x{pos-1:03x}")
        out.append(f"{'='*60}")

        # u16 flags
        flags = data[pos] | (data[pos+1] << 8); pos += 2
        idx = 0
        def gf(bits):
            nonlocal idx
            v = (flags >> idx) & ((1 << bits) - 1)
            idx += bits
            return v
        has_proto = gf(1); has_simple = gf(1); is_derived = gf(1)
        need_home = gf(1); func_kind = gf(2); new_tgt = gf(1)
        super_call = gf(1); super_allowed = gf(1); args_allowed = gf(1)
        has_debug = gf(1); bt_barrier = gf(1); is_eval = gf(1)

        # js_mode
        js_mode = data[pos]; pos += 1

        # func_name (bc_put_atom → LEB128)
        name_raw, pos = read_leb128(data, pos)
        func_name = resolve_bc_atom_leb(atoms, name_raw)

        # LEB128 header fields (layout varies by version)
        arg_count, pos = read_leb128(data, pos)
        var_count, pos = read_leb128(data, pos)
        def_arg_count, pos = read_leb128(data, pos)
        stack_size, pos = read_leb128(data, pos)
        # Frida v2 has NO var_ref_count; Bellard v5, NG v24 DO have it
        if vcfg is not None and vcfg.has_var_ref_count:
            _var_ref_count, pos = read_leb128(data, pos)
        closure_var_count, pos = read_leb128(data, pos)
        cpool_count, pos = read_leb128(data, pos)
        bc_len, pos = read_leb128(data, pos)

        out.append(f"  name={func_name} flags=0x{flags:04x} js_mode={js_mode}")
        out.append(f"  args={arg_count} vars={var_count} defargs={def_arg_count} stack={stack_size}")
        out.append(f"  closures={closure_var_count} cpool={cpool_count} bclen={bc_len}")
        out.append(f"  has_debug={has_debug}")

        # Vardefs: local_count then per-var
        local_count, pos = read_leb128(data, pos)
        out.append(f"  local_count={local_count}")
        varnames = {}
        for i in range(local_count):
            vn_raw, pos = read_leb128(data, pos)
            vn = resolve_bc_atom_leb(atoms, vn_raw)
            # Vardef layout differs by version:
            # Frida v2 + NG v24: scope_level, scope_next
            # Bellard v1/v5: scope_next, var_ref_idx
            if vcfg is None or vcfg.vardef_uses_scope_level:
                # Frida/NG style
                _scope_level, pos = read_leb128(data, pos)
                _scope_next, pos = read_leb128(data, pos)
            else:
                # Bellard v1/v5 style
                _scope_next, pos = read_leb128(data, pos)
                _var_ref_idx, pos = read_leb128(data, pos)
            vflags = data[pos]; pos += 1
            var_kind = vflags & 0xf
            is_const = (vflags >> 4) & 1
            is_lex = (vflags >> 5) & 1
            is_capt = (vflags >> 6) & 1
            varnames[i] = vn
            if i < 20 or i == local_count - 1:
                out.append(f"    [{i:2d}] {vn} kind={var_kind} const={is_const} lex={is_lex} capt={is_capt}")
            elif i == 20:
                out.append(f"    ... ({local_count - 20} more)")

        # Closure vars
        closure_names = {}
        for i in range(closure_var_count):
            cvn_raw, pos = read_leb128(data, pos)
            cvn = resolve_bc_atom_leb(atoms, cvn_raw)
            cv_idx, pos = read_leb128(data, pos)
            # Frida uses u8 for closure var flags, Bellard/NG use u16
            if vcfg and vcfg.name.startswith('frida'):
                cv_flags = data[pos]; pos += 1
            else:
                cv_flags = data[pos] | (data[pos+1] << 8); pos += 2
            is_local = cv_flags & 1
            is_arg = (cv_flags >> 1) & 1
            closure_names[i] = cvn
            out.append(f"    closure[{i}] {cvn} idx={cv_idx} local={is_local} arg={is_arg}")

        # Bytecode
        if pos + bc_len > len(data):
            out.append(f"  ERROR: bytecode extends past EOF (pos=0x{pos:03x} + {bc_len} > {len(data)})")
            bc_data = data[pos:]
            pos = len(data)
        else:
            bc_data = data[pos:pos+bc_len]
            pos += bc_len

        # Debug
        if has_debug:
            dbg_fn_raw, pos = read_leb128(data, pos)
            dbg_filename = resolve_bc_atom_leb(atoms, dbg_fn_raw)
            dbg_line, pos = read_leb128(data, pos)
            pc2line_len, pos = read_leb128(data, pos)
            pos += pc2line_len
            out.append(f"  debug: file={dbg_filename} line={dbg_line} pc2line={pc2line_len}b")

        # Build separate arg/loc/ref name maps
        # vardefs layout: [arg0, arg1, ..., argN-1, var0, var1, ..., varM-1]
        arg_names = {}
        loc_names = {}
        for i in range(local_count):
            if i < arg_count:
                arg_names[i] = varnames.get(i, f'arg_{i}')
            else:
                loc_names[i - arg_count] = varnames.get(i, f'loc_{i - arg_count}')

        # Disassemble
        out.append(f"\n  ── Disassembly ({bc_len} bytes) ──")
        instrs = disassemble(bc_data, atoms, closure_var_names=closure_names)
        for ins in instrs:
            raw = ' '.join(f'{b:02x}' for b in ins['raw'])
            out.append(f"    {ins['off']:4d} | {raw:<20s} | {ins['name']:<24s} {ins['desc']}")

        # Store function data for two-pass reconstruction
        parsed_functions.append({
            'func_num': func_num,
            'instrs': instrs,
            'arg_names': arg_names,
            'loc_names': loc_names,
            'closure_names': closure_names,
            'cpool_count': cpool_count,
            'arg_count': arg_count,
            'func_name': func_name,
            'parent_idx': current_parent if func_num > 0 else None,
        })

        # Track parent-child relationships
        if cpool_count > 0:
            child_start = func_num + 1
            # This function's children will be the next cpool_count functions
            # (only the ones that are 0x0E tags)
            parsed_functions[-1]['child_start'] = child_start

        # Cpool (child functions)
        child_func_count = 0
        for ci in range(cpool_count):
            if pos >= len(data):
                break
            cp_tag = data[pos]
            if cp_tag == bc_tag_func:
                child_func_count += 1
                pass  # parsed in next while loop iteration
            else:
                pos = skip_constant(data, pos)

        parsed_functions[-1]['child_func_count'] = child_func_count
        func_num += 1

    # ── Pass 2: Reconstruct with child function inlining ──
    # First reconstruct all child functions (leaf nodes first)
    for pf in reversed(parsed_functions):
        fn = pf['func_num']
        child_funcs_data = []

        if 'child_start' in pf:
            cs = pf['child_start']
            cc = pf.get('child_func_count', 0)
            for ci in range(cc):
                child_idx = cs + ci
                if child_idx < len(parsed_functions):
                    cpf = parsed_functions[child_idx]
                    # Build arg names string for the child
                    arg_strs = [cpf['arg_names'].get(i, f'arg_{i}') for i in range(cpf.get('arg_count', 0))]
                    # Filter out internal names
                    arg_strs = [a for a in arg_strs if a not in ('this',)]
                    child_funcs_data.append({
                        'arg_names_str': ', '.join(arg_strs),
                        'body_lines': cpf.get('reconstructed_lines', []),
                        'name': cpf.get('func_name', ''),
                    })

        pf_lines = reconstruct(
            pf['instrs'], pf['arg_names'], pf['loc_names'],
            pf['closure_names'], atoms,
            child_functions=child_funcs_data if child_funcs_data else None
        )
        
        # Filter out "this = this;" boilerplate
        pf_lines = [l for l in pf_lines if l.strip() != 'this = this;']
        
        # Reorder: move hoisted function declarations after const/var assignments
        # QuickJS emits define_func before const assignments, but original has them after
        func_decls = []
        other_lines = []
        in_func = False
        func_block = []
        for line in pf_lines:
            stripped = line.strip()
            if stripped.startswith('function ') and stripped.endswith('{'):
                in_func = True
                func_block = [line]
            elif in_func:
                func_block.append(line)
                if stripped == '}':
                    func_decls.append(func_block)
                    func_block = []
                    in_func = False
            else:
                other_lines.append(line)
        
        if func_decls:
            # Find insertion point: after last const/var assignment, before first call
            insert_idx = len(other_lines)
            for i, line in enumerate(other_lines):
                stripped = line.strip()
                # First line that's not a const/var assignment = insert functions before it
                if (stripped and 
                    not stripped.startswith('const ') and 
                    not stripped.startswith('var ') and
                    not stripped.startswith('//') and
                    '= new NativeFunction' not in stripped and
                    '= Process.' not in stripped and
                    '= Module.' not in stripped and
                    '= Memory.' not in stripped):
                    insert_idx = i
                    break
            
            reordered = other_lines[:insert_idx]
            for fb in func_decls:
                reordered.extend(fb)
            reordered.extend(other_lines[insert_idx:])
            pf_lines = reordered
        
        pf['reconstructed_lines'] = pf_lines

        out.append(f"\n  ── Reconstructed JS (Function #{fn}) ──")
        for line in pf_lines:
            out.append(f"    {line}")

    return '\n'.join(out), atoms


def skip_constant(data, pos):
    """Skip a serialized constant in the cpool"""
    if pos >= len(data):
        return pos
    tag = data[pos]; pos += 1
    if tag == 1: pass  # NULL
    elif tag == 2: pass  # UNDEFINED
    elif tag == 3: pass  # FALSE
    elif tag == 4: pass  # TRUE
    elif tag == 5: pos += 4  # INT32
    elif tag == 6: pos += 8  # FLOAT64
    elif tag == 7:  # STRING
        enc, pos = read_leb128(data, pos)
        slen = enc >> 1
        is_wide = enc & 1
        pos += slen * (2 if is_wide else 1)
    elif tag == 10:  # BIG_INT
        v, pos = read_leb128(data, pos)
        # skip v bytes
        pos += (v + 1) // 2
    elif tag == 11:  # BIG_FLOAT
        v, pos = read_leb128(data, pos)
        pos += (v + 1) // 2
    elif tag == 12:  # BIG_DECIMAL
        v, pos = read_leb128(data, pos)
        pos += v
    return pos


def disassemble(bc, atoms, closure_var_names=None):
    """Disassemble bytecode using the active opcode table.
    closure_var_names: dict mapping var_ref index → name (for Bellard/NG where get_var uses var_ref format)"""
    instrs = []
    pos = 0
    while pos < len(bc):
        op = bc[pos]
        op_entry = OP_MAP.get(op)
        if op_entry is None:
            instrs.append({'off': pos, 'op': op, 'name': f'db 0x{op:02x}', 'desc': '', 'raw': bc[pos:pos+1]})
            pos += 1
            continue
        name, size, fmt = op_entry
        if pos + size > len(bc):
            instrs.append({'off': pos, 'op': op, 'name': f'{name}[trunc]', 'desc': '', 'raw': bc[pos:]})
            break

        raw = bc[pos:pos+size]
        desc = ''
        operand = None

        try:
            if fmt == "none":
                pass
            elif fmt == "u8":
                operand = bc[pos+1]
                desc = str(operand)
            elif fmt == "i8":
                operand = struct.unpack_from('b', bc, pos+1)[0]
                desc = str(operand)
            elif fmt == "u16":
                operand = struct.unpack_from('<H', bc, pos+1)[0]
                desc = str(operand)
            elif fmt == "var_ref":
                # In Bellard/NG: var_ref indexes into closure_var table for names
                operand = struct.unpack_from('<H', bc, pos+1)[0]
                if closure_var_names and operand in closure_var_names:
                    desc = closure_var_names[operand]
                else:
                    desc = f"var_ref[{operand}]"
            elif fmt == "i16":
                operand = struct.unpack_from('<h', bc, pos+1)[0]
                desc = str(operand)
            elif fmt == "i32":
                operand = struct.unpack_from('<i', bc, pos+1)[0]
                desc = str(operand)
            elif fmt == "const":
                operand = struct.unpack_from('<I', bc, pos+1)[0]
                desc = f"const[{operand}]"
            elif fmt == "atom":
                raw_atom = struct.unpack_from('<I', bc, pos+1)[0]
                resolved = resolve_bc_atom(atoms, raw_atom)
                desc = resolved
                operand = resolved
            elif fmt == "npop":
                operand = struct.unpack_from('<H', bc, pos+1)[0]
                desc = f"argc={operand}"
            elif fmt == "label":
                rel = struct.unpack_from('<i', bc, pos+1)[0]
                target = (pos + 1) + rel  # relative to operand position
                desc = f"→ @{target}"
                operand = target
            elif fmt == "label8":
                rel = struct.unpack_from('b', bc, pos+1)[0]
                target = (pos + 1) + rel  # relative to operand position
                desc = f"→ @{target}"
                operand = target
            elif fmt == "label16":
                rel = struct.unpack_from('<h', bc, pos+1)[0]
                target = (pos + 1) + rel  # relative to operand position
                desc = f"→ @{target}"
                operand = target
            elif fmt == "atom_u8":
                raw_atom = struct.unpack_from('<I', bc, pos+1)[0]
                resolved = resolve_bc_atom(atoms, raw_atom)
                u8v = bc[pos+5]
                desc = f"{resolved}, {u8v}"
                operand = (resolved, u8v)
            elif fmt == "atom_label_u8":
                raw_atom = struct.unpack_from('<I', bc, pos+1)[0]
                resolved = resolve_bc_atom(atoms, raw_atom)
                rel = struct.unpack_from('<i', bc, pos+5)[0]
                u8v = bc[pos+9]
                desc = f"{resolved}, → @{pos+rel}, {u8v}"
            elif fmt == "atom_u16":
                raw_atom = struct.unpack_from('<I', bc, pos+1)[0]
                resolved = resolve_bc_atom(atoms, raw_atom)
                u16v = struct.unpack_from('<H', bc, pos+5)[0]
                desc = f"{resolved}, {u16v}"
            elif fmt == "npop_u16":
                npop = struct.unpack_from('<H', bc, pos+1)[0]
                u16v = struct.unpack_from('<H', bc, pos+3)[0]
                desc = f"argc={npop}, {u16v}"
        except (struct.error, IndexError):
            desc = "[error]"

        instrs.append({
            'off': pos, 'op': op, 'name': name, 'desc': desc,
            'raw': raw, 'operand': operand, 'fmt': fmt
        })
        pos += size

    return instrs


def reconstruct(instrs, arg_names, loc_names, closure_names, atoms, child_functions=None):
    """Stack-based JS reconstruction.
    arg_names: get_arg N → arg_names[N]
    loc_names: get_loc N → loc_names[N]
    closure_names: get_var_ref N → closure_names[N]"""
    # Detect internal names to suppress
    _internal_names = {'<ret>', '<var>', '<arg_var>', '<with>', '<eval>', '<null>'}

    # Pre-scan: build control flow structure
    # Pattern 1 - while: if_false @exit ... goto @before_if (backward) → @exit: close
    # Pattern 2 - if/else: if_false @else ... goto @end (forward) ... @else: else ... @end: close  
    # Pattern 3 - if (no else): if_false @end ... @end: close (no goto between)
    close_brace_at = {}  # offset → '}' or '} else {'
    while_headers = set()  # offsets where 'while' condition starts

    # Build instruction offset → index map
    off_to_idx = {ins['off']: i for i, ins in enumerate(instrs)}

    # Track nesting depth for braces
    forward_goto_targets = {}  # target_offset → count of gotos pointing here
    if_false_targets = set()  # offsets where if_false points (= else start or if-end)
    goto_sources = {}  # goto_offset → target_offset

    do_while_headers = set()  # offsets where do-while body starts (need 'do {')
    do_while_tails = set()  # offsets of backward if_true/if_false (= do-while condition)

    for idx_i, ins in enumerate(instrs):
        if ins['name'] in ('goto', 'goto8', 'goto16'):
            target = ins.get('operand', 0)
            if isinstance(target, int):
                goto_sources[ins['off']] = target
                if target < ins['off']:
                    # BACKWARD goto → while loop
                    while_headers.add(target)
                    if idx_i + 1 < len(instrs):
                        close_brace_at[instrs[idx_i + 1]['off']] = '}'
                else:
                    # FORWARD goto → end of then-block
                    forward_goto_targets[target] = forward_goto_targets.get(target, 0) + 1

        if ins['name'] in ('if_false', 'if_false8', 'if_true', 'if_true8'):
            target = ins.get('operand', 0)
            if isinstance(target, int):
                if target < ins['off']:
                    # BACKWARD conditional jump → do-while loop
                    do_while_headers.add(target)
                    do_while_tails.add(ins['off'])
                else:
                    # FORWARD conditional jump → if/else
                    if_false_targets.add(target)

    # Now determine what goes where (only for FORWARD conditional jumps)
    for idx_i, ins in enumerate(instrs):
        if ins['name'] in ('if_false', 'if_false8', 'if_true', 'if_true8'):
            target = ins.get('operand', 0)
            if not isinstance(target, int):
                continue
            if target <= ins['off']:
                continue  # backward jump = do-while, handled separately
            
            # Check if there's a forward goto just before the target (= if/else)
            has_else = False
            for j in range(idx_i + 1, len(instrs)):
                if instrs[j]['off'] >= target:
                    break
                if instrs[j]['name'] in ('goto', 'goto8', 'goto16'):
                    goto_target = instrs[j].get('operand', 0)
                    if isinstance(goto_target, int) and goto_target > target:
                        has_else = True
                        break

            if not has_else:
                # if without else — close brace at target
                if target not in close_brace_at:
                    close_brace_at[target] = '}'

    # For forward gotos: closing brace at target (one '}' total, 
    # since the goto instruction itself emits '} else {' or '}')
    # We only need a final '}' at the ultimate target where all paths converge
    for target, count in forward_goto_targets.items():
        if target not in close_brace_at:
            close_brace_at[target] = '}'
    S = []  # stack
    L = []  # output lines

    def pop():
        return S.pop() if S else '?'
    def peek():
        return S[-1] if S else '?'

    _pending_close = None
    _brace_depth = 0  # track open { count
    _if_depth = {}  # if_false_offset → brace_depth
    _method_buffer = []  # buffered method definitions for object literals

    for ins_idx, ins in enumerate(instrs):
        n = ins['name']
        o = ins.get('operand')
        d = ins['desc']
        off = ins['off']

        # Emit deferred closing brace from previous iteration
        if _pending_close is not None:
            for brace_line in _pending_close.strip().split('\n'):
                bl = brace_line.strip()
                if bl:
                    L.append(bl)
                    _brace_depth -= bl.count('}')
                    _brace_depth += bl.count('{')
            _pending_close = None
        if off in close_brace_at:
            _pending_close = close_brace_at[off]

        # Emit 'do {' at do-while body start
        if off in do_while_headers:
            L.append('do {')
            _brace_depth += 1

        # Push constants
        if n.startswith('push_') and n[5:].isdigit():
            S.append(n[5:]); continue
        if n == 'push_minus1': S.append('-1'); continue
        if n == 'push_i8' or n == 'push_i16' or n == 'push_i32':
            S.append(str(o)); continue
        if n == 'undefined': S.append('undefined'); continue
        if n == 'null': S.append('null'); continue
        if n == 'push_this': S.append('this'); continue
        if n == 'push_false': S.append('false'); continue
        if n == 'push_true': S.append('true'); continue
        if n == 'push_empty_string': S.append('""'); continue
        if n == 'object': S.append('{}'); continue
        if n == 'push_atom_value': S.append(f'"{d}"'); continue

        # Variables
        if n == 'get_var' or n == 'get_var_undef' or n == 'check_var':
            S.append(d); continue
        if n == 'put_var' or n == 'put_var_init':
            L.append(f'{"const " if n == "put_var_init" else ""}{d} = {pop()};'); continue
        if n == 'put_var_strict':
            L.append(f'{d} = {pop()};'); continue

        # Locals
        # Variable access patterns
        var_matched = False
        for pfx, base_type in [('get_loc', 'loc'), ('put_loc', 'loc'), ('set_loc', 'loc'),
                          ('get_arg', 'arg'), ('put_arg', 'arg'), ('set_arg', 'arg'),
                          ('get_var_ref', 'ref'), ('put_var_ref', 'ref'), ('set_var_ref', 'ref')]:
            if n.startswith(pfx):
                # Extract index from opcode name
                suffix = n[len(pfx):]
                if suffix == '':
                    idx = o if isinstance(o, int) else int(d) if d.isdigit() else 0
                elif suffix == '8':
                    idx = o if isinstance(o, int) else int(d) if d.isdigit() else 0
                elif suffix == '_check' or suffix == '_check_init' or suffix == '_checkthis' or suffix == '_uninitialized':
                    idx = o if isinstance(o, int) else int(d) if d.isdigit() else 0
                elif len(suffix) == 1 and suffix.isdigit():
                    idx = int(suffix)
                else:
                    continue  # not this prefix

                if base_type == 'loc':
                    vn = loc_names.get(idx, f'loc_{idx}')
                elif base_type == 'ref':
                    vn = closure_names.get(idx, f'ref_{idx}')
                else:
                    vn = arg_names.get(idx, f'arg_{idx}')

                if 'get' in pfx:
                    S.append(vn)
                elif 'put' in pfx:
                    val = pop()
                    if vn not in _internal_names:
                        L.append(f'{vn} = {val};')
                    else:
                        # <ret> = expr → emit as statement if it has side effects
                        # BUT skip if the expression is already in the previous line
                        if val and val != '?' and ('(' in val or '=' in val):
                            already_emitted = L and val in L[-1] if L else False
                            if not already_emitted:
                                L.append(f'{val};')
                elif 'set' in pfx:
                    if '_uninitialized' not in n:
                        val = pop()
                        if vn not in _internal_names:
                            L.append(f'{vn} = {val};')
                            S.append(vn)
                        else:
                            if val and val != '?' and ('(' in val or '=' in val):
                                already_emitted = L and val in L[-1] if L else False
                                if not already_emitted:
                                    L.append(f'{val};')
                            S.append(val)
                var_matched = True
                break
        if var_matched:
            continue
        else:
            # Fields
            if n == 'get_field':
                S.append(f'{pop()}.{d}'); continue
            if n == 'get_field2':
                obj = peek()
                S.append(f'{obj}.{d}'); continue
            if n == 'put_field':
                val = pop(); obj = pop()
                L.append(f'{obj}.{d} = {val};'); continue
            if n == 'define_field':
                val = pop(); obj = peek()
                # Check if val is a closure — if so, buffer as method for object literal
                child_idx = None
                if isinstance(val, str) and val.startswith('<fn_'):
                    try:
                        child_idx = int(val[4:-1])
                    except:
                        pass
                if child_idx is not None and child_functions and child_idx < len(child_functions):
                    cf = child_functions[child_idx]
                    cf_args = cf.get('arg_names_str', 'args')
                    cf_body = cf.get('body_lines', [])
                    method_lines = [f'  {d}: function({cf_args}) {{']
                    for bl in cf_body:
                        method_lines.append(f'    {bl}')
                    method_lines.append('  },')
                    _method_buffer.append('\n'.join(method_lines))
                else:
                    L.append(f'{obj}.{d} = {val};')
                continue
            if n == 'get_array_el':
                idx_v = pop(); arr = pop()
                S.append(f'{arr}[{idx_v}]'); continue
            if n == 'put_array_el':
                val = pop(); idx_v = pop(); arr = pop()
                L.append(f'{arr}[{idx_v}] = {val};'); continue
            if n == 'get_length':
                S.append(f'{pop()}.length'); continue

            # Calls
            if n in ('call', 'tail_call', 'call0', 'call1', 'call2', 'call3'):
                if n in ('call0', 'call1', 'call2', 'call3'):
                    argc = int(n[-1])
                else:
                    argc = o if isinstance(o, int) else 0
                args = [pop() for _ in range(argc)][::-1]
                fn = pop()
                expr = f'{fn}({", ".join(args)})'
                if 'tail' in n: L.append(f'return {expr};')
                else: S.append(expr)
                continue
            if n in ('call_method', 'tail_call_method'):
                argc = o if isinstance(o, int) else 0
                args = [pop() for _ in range(argc)][::-1]
                method = pop(); obj = pop()
                
                # Check if any arg is '{}' and we have buffered methods
                method_buf = _method_buffer
                if method_buf:
                    for ai, arg in enumerate(args):
                        if arg == '{}':
                            # Replace {} with object containing methods
                            methods_str = '\n'.join(method_buf)
                            args[ai] = '{\n' + methods_str + '\n}'
                            break
                pass
                
                if '.' in str(method):
                    expr = f'{method}({", ".join(args)})'
                else:
                    expr = f'{obj}.{method}({", ".join(args)})'
                if 'tail' in n: L.append(f'return {expr};')
                else: S.append(expr)
                continue
            if n == 'call_constructor':
                argc = o if isinstance(o, int) else 0
                args = [pop() for _ in range(argc)][::-1]
                ctor = pop(); _ = pop()
                S.append(f'new {ctor}({", ".join(args)})'); continue
            if n == 'array_from':
                argc = o if isinstance(o, int) else 0
                args = [pop() for _ in range(argc)][::-1]
                S.append(f'[{", ".join(args)}]'); continue

            # Returns
            if n == 'return':
                val = pop()
                if val in _internal_names:
                    pass  # suppress "return <ret>;"
                else:
                    # Check if this duplicates the last line (common in top-level evals)
                    ret_line = f'{val};'
                    if L and L[-1] == ret_line:
                        pass  # suppress duplicate
                    else:
                        L.append(f'return {val};')
                continue
            if n == 'return_undef':
                # Flush any remaining stack as statements (side-effect expressions)
                while S:
                    v = S.pop(0)
                    if v and v != '?' and '(' in v:
                        L.append(f'{v};')
                # Only emit explicit return if inside a named function (not top-level)
                is_toplevel = not any(n2 in arg_names.values() for n2 in ['args', 'retval'])
                if not is_toplevel:
                    pass  # suppress "return;" in top-level
                # Always add return for clarity in non-trivial functions
                continue

            # Closures
            if n in ('fclosure', 'fclosure8', 'push_const', 'push_const8'):
                idx = o if isinstance(o, int) else 0
                tag = 'fn' if 'closure' in n else 'const'
                S.append(f'<{tag}_{idx}>')
                continue

            # Stack ops
            if n == 'drop':
                v = pop()
                # After dup+put_var+drop, the drop is just discarding the dup'd value
                # Only emit as statement if it looks like a real side-effect call
                if v and v != '?' and '(' in v and not any(v == prev_val for prev_val in [l.rstrip(';') for l in L[-2:]]):
                    L.append(f'{v};')
                continue
            if n == 'dup': S.append(peek()); continue
            if n == 'dup2':
                if len(S) >= 2: S.extend([S[-2], S[-1]])
                continue
            if n == 'swap':
                if len(S) >= 2: S[-1], S[-2] = S[-2], S[-1]
                continue
            if n == 'nip':
                if len(S) >= 2: del S[-2]
                continue
            if n == 'rot3l':
                if len(S) >= 3: v = S.pop(-3); S.append(v)
                continue
            if n == 'insert2':
                # a b → b a b  (dup_x1: insert copy of top under second)
                if len(S) >= 2:
                    b = S[-1]
                    S.insert(-2, b)
                continue

            # Arithmetic
            binops = {'add':'+', 'sub':'-', 'mul':'*', 'div':'/', 'mod':'%', 'pow':'**',
                     'shl':'<<', 'sar':'>>', 'shr':'>>>', 'and':'&', 'or':'|', 'xor':'^',
                     'lt':'<', 'lte':'<=', 'gt':'>', 'gte':'>=',
                     'eq':'==', 'neq':'!=', 'strict_eq':'===', 'strict_neq':'!==',
                     'in':'in', 'instanceof':'instanceof'}
            if n in binops:
                b = pop(); a = pop()
                S.append(f'{a} {binops[n]} {b}'); continue

            unops = {'neg':'-', 'plus':'+', 'not':'~', 'lnot':'!', 'typeof':'typeof ', 'inc':'++', 'dec':'--'}
            if n in unops:
                v = pop()
                if n in ('inc', 'dec'):
                    S.append(f'{v}{unops[n][0]}1' if n == 'inc' else f'{v}-1')
                else:
                    S.append(f'{unops[n]}{v}')
                continue

            if n == 'is_undefined': S.append(f'{pop()} === undefined'); continue
            if n == 'is_null': S.append(f'{pop()} === null'); continue
            if n == 'is_undefined_or_null': S.append(f'{pop()} == null'); continue
            if n == 'typeof_is_undefined': S.append(f'typeof {pop()} === "undefined"'); continue
            if n == 'typeof_is_function': S.append(f'typeof {pop()} === "function"'); continue

            # Compound assignment shortcuts
            if n == 'add_loc':
                idx = o if isinstance(o, int) else int(d) if d.isdigit() else 0
                vn = loc_names.get(idx, f'loc_{idx}')
                val = pop()
                L.append(f'{vn} = {vn} + {val};')
                continue
            if n == 'inc_loc':
                idx = o if isinstance(o, int) else int(d) if d.isdigit() else 0
                vn = loc_names.get(idx, f'loc_{idx}')
                L.append(f'{vn} = {vn} + 1;')
                continue
            if n == 'dec_loc':
                idx = o if isinstance(o, int) else int(d) if d.isdigit() else 0
                vn = loc_names.get(idx, f'loc_{idx}')
                L.append(f'{vn} = {vn} - 1;')
                continue

            # Control flow
            if n in ('if_false', 'if_false8'):
                cond = pop()
                target = o if isinstance(o, int) else 0

                # Detect ternary/conditional expression pattern:
                # if_false @E; [expr]; goto @END; @E: [expr]; @END: consume
                # Find the goto that ends the then-branch
                then_goto_idx = None
                for ti in range(ins_idx + 1, min(ins_idx + 8, len(instrs))):
                    if instrs[ti]['name'] in ('goto', 'goto8', 'goto16'):
                        tgt = instrs[ti].get('operand', 0)
                        if isinstance(tgt, int) and tgt > instrs[ti]['off']:
                            then_goto_idx = ti
                            break
                    if instrs[ti]['off'] >= target:
                        break  # reached else block without finding goto

                if then_goto_idx is not None:
                    goto_ins = instrs[then_goto_idx]
                    end_target = goto_ins.get('operand', 0)
                    else_start_idx = then_goto_idx + 1
                    # Find the instruction at end_target
                    end_idx = None
                    for ei in range(else_start_idx, min(else_start_idx + 8, len(instrs))):
                        if instrs[ei]['off'] >= end_target:
                            end_idx = ei
                            break

                    if end_idx is not None and else_start_idx < end_idx:
                        # Check if the instruction at end_target is a consumer (put_var, put_loc, set_loc, etc.)
                        end_ins = instrs[end_idx]
                        is_consumer = end_ins['name'] in ('put_var', 'put_var_init', 'put_loc', 'put_loc0', 'put_loc1', 'put_loc2', 'put_loc3', 'put_loc8', 'set_loc', 'set_loc0', 'set_loc1', 'set_loc2', 'set_loc3', 'set_loc8')

                        then_len = then_goto_idx - (ins_idx + 1)
                        else_len = end_idx - else_start_idx

                        if is_consumer and then_len <= 6 and else_len <= 6:
                            # It's a conditional expression! Simulate both branches
                            then_instrs = instrs[ins_idx+1:then_goto_idx]
                            else_instrs = instrs[else_start_idx:end_idx]

                            # Mini stack sim for each branch
                            def mini_sim(branch_instrs):
                                ms = list(S)  # copy current stack
                                for bi in branch_instrs:
                                    bn = bi['name']
                                    bo = bi.get('operand')
                                    bd = bi.get('desc', '')
                                    if bn.startswith('push_') and bn[5:].isdigit():
                                        ms.append(bn[5:])
                                    elif bn in ('push_i8','push_i16','push_i32'):
                                        ms.append(str(bo))
                                    elif bn == 'push_atom_value':
                                        ms.append(f'"{bd}"')
                                    elif bn == 'push_empty_string': ms.append('""')
                                    elif bn == 'undefined': ms.append('undefined')
                                    elif bn == 'null': ms.append('null')
                                    elif bn in ('push_true',): ms.append('true')
                                    elif bn in ('push_false',): ms.append('false')
                                    elif bn.startswith('get_var'):
                                        ms.append(bd if bd else str(bo))
                                    elif bn.startswith('get_loc'):
                                        suffix = bn[7:]
                                        if suffix and suffix.isdigit(): idx2 = int(suffix)
                                        elif suffix == '8': idx2 = bo if isinstance(bo,int) else 0
                                        else: idx2 = bo if isinstance(bo,int) else 0
                                        ms.append(loc_names.get(idx2, f'loc_{idx2}'))
                                    elif bn.startswith('get_arg'):
                                        suffix = bn[7:]
                                        if suffix and suffix.isdigit(): idx2 = int(suffix)
                                        else: idx2 = bo if isinstance(bo,int) else 0
                                        ms.append(arg_names.get(idx2, f'arg_{idx2}'))
                                    elif bn == 'get_field':
                                        ms.append(f'{ms.pop()}.{bd}' if ms else f'?.{bd}')
                                    elif bn == 'get_field2':
                                        obj2 = ms[-1] if ms else '?'
                                        ms.append(f'{obj2}.{bd}')
                                    elif bn in ('mul',): b2=ms.pop() if ms else '?'; a2=ms.pop() if ms else '?'; ms.append(f'{a2} * {b2}')
                                    elif bn in ('div',): b2=ms.pop() if ms else '?'; a2=ms.pop() if ms else '?'; ms.append(f'{a2} / {b2}')
                                    elif bn in ('add',): b2=ms.pop() if ms else '?'; a2=ms.pop() if ms else '?'; ms.append(f'{a2} + {b2}')
                                    elif bn in ('sub',): b2=ms.pop() if ms else '?'; a2=ms.pop() if ms else '?'; ms.append(f'{a2} - {b2}')
                                    elif bn in ('mod',): b2=ms.pop() if ms else '?'; a2=ms.pop() if ms else '?'; ms.append(f'{a2} % {b2}')
                                    elif bn in ('neg',): ms.append(f'-{ms.pop()}' if ms else '-?')
                                    elif bn in ('lnot',): ms.append(f'!{ms.pop()}' if ms else '!?')
                                    elif bn == 'call_method':
                                        argc2 = bo if isinstance(bo,int) else 0
                                        args2 = [ms.pop() if ms else '?' for _ in range(argc2)][::-1]
                                        m2 = ms.pop() if ms else '?'
                                        o2 = ms.pop() if ms else '?'
                                        ms.append(f'{o2}.{m2}({",".join(args2)})')
                                return ms[-1] if ms else '?'

                            then_val = mini_sim(then_instrs)
                            else_val = mini_sim(else_instrs)
                            S.append(f'{cond} ? {then_val} : {else_val}')

                            # NOP out processed instructions
                            for ni in range(ins_idx+1, end_idx):
                                instrs[ni]['name'] = 'nop'
                            if isinstance(end_target, int) and end_target in close_brace_at:
                                del close_brace_at[end_target]
                            if target in close_brace_at:
                                del close_brace_at[target]
                            continue

                if ins_idx + 3 < len(instrs):
                    next1 = instrs[ins_idx + 1]
                    next2 = instrs[ins_idx + 2]
                    is_push1 = next1['name'].startswith('push_') or next1['name'] in ('push_atom_value', 'push_empty_string', 'undefined', 'null', 'push_this', 'push_false', 'push_true', 'get_var', 'get_var_undef', 'get_loc', 'get_loc0', 'get_loc1', 'get_loc2', 'get_loc3', 'get_loc8', 'get_arg', 'get_arg0', 'get_arg1', 'get_arg2', 'get_arg3')
                    is_goto = next2['name'] in ('goto', 'goto8', 'goto16')
                    if is_push1 and is_goto:
                        goto_target = next2.get('operand', 0)
                        # Find the else push
                        else_idx = ins_idx + 3
                        if else_idx < len(instrs):
                            else_ins = instrs[else_idx]
                            is_push2 = else_ins['name'].startswith('push_') or else_ins['name'] in ('push_atom_value', 'push_empty_string', 'undefined', 'null', 'push_this', 'push_false', 'push_true', 'get_var', 'get_var_undef', 'get_loc', 'get_loc0', 'get_loc1', 'get_loc2', 'get_loc3', 'get_loc8', 'get_arg', 'get_arg0', 'get_arg1', 'get_arg2', 'get_arg3')
                            if is_push2 and else_ins['off'] == target:
                                # This is a ternary! Handle inline
                                # Get then-value
                                then_val = next1.get('operand')
                                if next1['name'] == 'push_atom_value':
                                    then_val = f'"{next1["desc"]}"'
                                elif next1['name'] in ('push_empty_string',):
                                    then_val = '""'
                                elif next1['name'] in ('undefined',):
                                    then_val = 'undefined'
                                elif next1['name'] in ('null',):
                                    then_val = 'null'
                                elif next1['name'] in ('push_true',):
                                    then_val = 'true'
                                elif next1['name'] in ('push_false',):
                                    then_val = 'false'
                                elif next1['name'].startswith('push_') and next1['name'][-1].isdigit() and not next1['name'].endswith('8') and not next1['name'].endswith('16') and not next1['name'].endswith('32'):
                                    then_val = next1['name'].split('_')[-1]
                                elif next1['name'] in ('push_i8', 'push_i16', 'push_i32'):
                                    then_val = str(next1.get('operand', 0))
                                elif next1['name'].startswith('get_'):
                                    then_val = next1.get('desc', next1.get('operand', '?'))
                                else:
                                    then_val = str(next1.get('operand', '?'))

                                else_val = else_ins.get('operand')
                                if else_ins['name'] == 'push_atom_value':
                                    else_val = f'"{else_ins["desc"]}"'
                                elif else_ins['name'] in ('push_empty_string',):
                                    else_val = '""'
                                elif else_ins['name'] in ('undefined',):
                                    else_val = 'undefined'
                                elif else_ins['name'] in ('null',):
                                    else_val = 'null'
                                elif else_ins['name'] in ('push_true',):
                                    else_val = 'true'
                                elif else_ins['name'] in ('push_false',):
                                    else_val = 'false'
                                elif else_ins['name'].startswith('push_') and else_ins['name'][-1].isdigit() and not else_ins['name'].endswith('8') and not else_ins['name'].endswith('16') and not else_ins['name'].endswith('32'):
                                    else_val = else_ins['name'].split('_')[-1]
                                elif else_ins['name'] in ('push_i8', 'push_i16', 'push_i32'):
                                    else_val = str(else_ins.get('operand', 0))
                                elif else_ins['name'].startswith('get_'):
                                    else_val = else_ins.get('desc', else_ins.get('operand', '?'))
                                else:
                                    else_val = str(else_ins.get('operand', '?'))

                                S.append(f'{cond} ? {then_val} : {else_val}')
                                # Skip the next 3 instructions (push, goto, push)
                                # We mark them to be skipped
                                instrs[ins_idx + 1]['name'] = 'nop'
                                instrs[ins_idx + 2]['name'] = 'nop'
                                instrs[ins_idx + 3]['name'] = 'nop'
                                # Remove close_brace for this pattern
                                if isinstance(goto_target, int) and goto_target in close_brace_at:
                                    del close_brace_at[goto_target]
                                if target in close_brace_at:
                                    del close_brace_at[target]
                                continue

                if off in do_while_tails:
                    # do-while: backward if_false means "continue if true"
                    L.append(f'}} while ({cond});')
                    _brace_depth -= 1
                    continue
                is_while = off in while_headers or (ins_idx > 0 and any(
                    instrs[ins_idx-k]['off'] in while_headers 
                    for k in range(1, min(6, ins_idx+1)) if ins_idx-k >= 0))
                _if_depth[target] = _brace_depth
                if is_while:
                    L.append(f'while ({cond}) {{')
                else:
                    L.append(f'if ({cond}) {{')
                _brace_depth += 1
                continue
            if n in ('if_true', 'if_true8'):
                cond = pop()
                target = o if isinstance(o, int) else 0
                if off in do_while_tails:
                    # do-while: backward if_true means "continue while cond"
                    L.append(f'}} while ({cond});')
                    _brace_depth -= 1
                    continue
                is_while = off in while_headers or (ins_idx > 0 and any(
                    instrs[ins_idx-k]['off'] in while_headers 
                    for k in range(1, min(6, ins_idx+1)) if ins_idx-k >= 0))
                _if_depth[target] = _brace_depth
                if is_while:
                    L.append(f'while (!({cond})) {{')
                else:
                    L.append(f'if (!({cond})) {{')
                _brace_depth += 1
                continue
            if n in ('goto', 'goto8', 'goto16'):
                target = o if isinstance(o, int) else 0
                if target < off:
                    # Backward jump → end of while loop body (close handled by close_brace_at)
                    pass
                else:
                    next_off = instrs[ins_idx + 1]['off'] if ins_idx + 1 < len(instrs) else -1
                    if next_off in if_false_targets:
                        # Close nested blocks down to the depth of the if that targets next_off
                        target_depth = _if_depth.get(next_off, _brace_depth - 1)
                        extra_closes = _brace_depth - target_depth - 1
                        for _ in range(extra_closes):
                            L.append('}')
                            _brace_depth -= 1
                        L.append('} else {')
                        # depth stays same (closed one, opened one)
                    else:
                        L.append('}')
                        _brace_depth -= 1
                continue

            # Define var/func
            if n == 'define_var' or n == 'check_define_var':
                resolved, kind = o if isinstance(o, tuple) else (d, 0)
                continue
            if n == 'define_func':
                resolved, kind = o if isinstance(o, tuple) else (d.split(',')[0].strip() if ',' in d else d, 0)
                v = pop()
                # Try to inline function definition
                child_idx = None
                if v.startswith('<fn_'):
                    try:
                        child_idx = int(v[4:-1])
                    except:
                        pass
                if child_idx is not None and child_functions and child_idx < len(child_functions):
                    cf = child_functions[child_idx]
                    cf_args = cf.get('arg_names_str', '')
                    cf_body = cf.get('body_lines', [])
                    L.append(f'function {resolved}({cf_args}) {{')
                    for bl in cf_body:
                        L.append(f'  {bl}')
                    L.append('}')
                else:
                    L.append(f'function {resolved}() {{ /* <fn_{child_idx}> */ }}')
                continue

            # Misc
            if n in ('to_object', 'to_propkey', 'to_propkey2', 'nop', 'check_brand',
                     'add_brand', 'special_object', 'nip_catch', 'set_name',
                     'set_home_object', 'set_name_computed', 'set_proto',
                     'check_ctor', 'check_ctor_return', 'close_loc',
                     'set_loc_uninitialized', 'rest', 'iterator_check_object',
                     'iterator_get_value_done', 'for_of_next', 'for_in_next'):
                continue

            if n == 'throw': L.append(f'throw {pop()};'); continue
            if n == 'catch': S.append('<error>'); continue
            if n == 'define_method':
                resolved, kind = o if isinstance(o, tuple) else (d.split(',')[0].strip() if ',' in d else d, 0)
                val = pop(); obj = pop()
                # Buffer method definition for inlining into object literal
                child_idx = None
                if val.startswith('<fn_'):
                    try:
                        child_idx = int(val[4:-1])
                    except:
                        pass
                if child_idx is not None and child_functions and child_idx < len(child_functions):
                    cf = child_functions[child_idx]
                    cf_args = cf.get('arg_names_str', 'args')
                    cf_body = cf.get('body_lines', [])
                    method_lines = [f'  {resolved}({cf_args}) {{']
                    for bl in cf_body:
                        method_lines.append(f'    {bl}')
                    method_lines.append('  },')
                    # Store on the object representation
                    pass; 
                    pass
                    _method_buffer.append('\n'.join(method_lines))
                else:
                    pass; 
                    pass
                    _method_buffer.append(f'  // {resolved}: {val}')
                S.append(obj)
                continue
            if n == 'define_method_computed':
                val = pop(); key = pop(); obj = pop()
                L.append(f'// {obj}[{key}] = {val}')
                S.append(obj)
                continue

    if _pending_close is not None:
        for brace_line in _pending_close.strip().split('\n'):
            if brace_line.strip():
                L.append(brace_line.strip())
    if S:
        L.append(f'// remaining stack: {S}')
    return L


def main():
    if len(sys.argv) < 2:
        print("Usage: python frida_decompile.py <file> [output]")
        sys.exit(1)

    with open(sys.argv[1], 'rb') as f:
        data = f.read()

    result, atoms = parse_file(data)
    print(result)

    if len(sys.argv) > 2:
        with open(sys.argv[2], 'w') as f:
            f.write(result)
        print(f"\n[*] Written to {sys.argv[2]}")


if __name__ == '__main__':
    main()
