#!/usr/bin/env python3
"""
QuickJS version configuration tables.
Generated from actual source code of each QuickJS variant.
"""

import struct

# ── VERSION DETECTION ──────────────────────────────────────────────────────

def detect_version(data):
    """Detect QuickJS bytecode version and return config dict."""
    if len(data) < 2:
        raise ValueError("File too small")
    
    v = data[0]
    be = v & 0x40  # big-endian flag
    base = v & ~0x40
    
    configs = {
        1:  'bellard_v1',    # upstream, no bignum, no CONFIG_BIGNUM
        2:  'frida_v2',      # frida fork, CONFIG_BIGNUM
        5:  'bellard_v5',    # upstream current
        24: 'ng_v24',        # quickjs-ng
    }
    
    name = configs.get(base, f'unknown_v{base}')
    return {
        'version': v,
        'base_version': base,
        'big_endian': bool(be),
        'name': name,
        'display': f'{name}{"_BE" if be else ""}',
    }


# ── VARIANT CONFIGURATIONS ─────────────────────────────────────────────────

class VersionConfig:
    def __init__(self, name, bc_tag_func, first_atom, has_var_ref_count, 
                 vardef_uses_scope_level, opcode_table, atom_table, big_endian=False):
        self.name = name
        self.bc_tag_func = bc_tag_func        # value of BC_TAG_FUNCTION_BYTECODE
        self.first_atom = first_atom          # JS_ATOM_END value
        self.has_var_ref_count = has_var_ref_count  # is var_ref_count in header?
        self.vardef_uses_scope_level = vardef_uses_scope_level  # scope_level vs scope_next+varef_idx
        self.opcode_table = opcode_table      # list of (name, size, fmt)
        self.atom_table = atom_table          # list of built-in atom strings (index = atom_id)
        self.big_endian = big_endian

    def u16(self, data, pos):
        if self.big_endian:
            return struct.unpack_from('>H', data, pos)[0], pos + 2
        return struct.unpack_from('<H', data, pos)[0], pos + 2

    def u32(self, data, pos):
        if self.big_endian:
            return struct.unpack_from('>I', data, pos)[0], pos + 4
        return struct.unpack_from('<I', data, pos)[0], pos + 4

    def i32(self, data, pos):
        if self.big_endian:
            return struct.unpack_from('>i', data, pos)[0], pos + 4
        return struct.unpack_from('<i', data, pos)[0], pos + 4

    def resolve_atom(self, custom_atoms, raw_u32):
        """Resolve bytecode atom u32 to string."""
        if raw_u32 < self.first_atom:
            if raw_u32 < len(self.atom_table):
                return self.atom_table[raw_u32]
            return f'<builtin_{raw_u32}>'
        idx = raw_u32 - self.first_atom
        if idx < len(custom_atoms):
            return custom_atoms[idx]
        return f'<custom_{idx}>'

    def resolve_atom_leb(self, custom_atoms, raw_leb):
        """Resolve header atom (bc_put_atom / bc_get_atom LEB128 encoding)."""
        if raw_leb & 1:
            return str(raw_leb >> 1)  # tagged integer
        idx = raw_leb >> 1
        if idx < self.first_atom:
            if idx < len(self.atom_table):
                return self.atom_table[idx]
            return f'<builtin_{idx}>'
        custom_idx = idx - self.first_atom
        if custom_idx < len(custom_atoms):
            return custom_atoms[custom_idx]
        return f'<custom_{custom_idx}>'


# ── OPCODE TABLES ─────────────────────────────────────────────────────────

FRIDA_OPCODE_TABLE = [('invalid', 1, 'none'), ('push_i32', 5, 'i32'), ('push_const', 5, 'const'), ('fclosure', 5, 'const'), ('push_atom_value', 5, 'atom'), ('private_symbol', 5, 'atom'), ('undefined', 1, 'none'), ('null', 1, 'none'), ('push_this', 1, 'none'), ('push_false', 1, 'none'), ('push_true', 1, 'none'), ('object', 1, 'none'), ('special_object', 2, 'u8'), ('rest', 3, 'u16'), ('drop', 1, 'none'), ('nip', 1, 'none'), ('nip1', 1, 'none'), ('dup', 1, 'none'), ('dup1', 1, 'none'), ('dup2', 1, 'none'), ('dup3', 1, 'none'), ('insert2', 1, 'none'), ('insert3', 1, 'none'), ('insert4', 1, 'none'), ('perm3', 1, 'none'), ('perm4', 1, 'none'), ('perm5', 1, 'none'), ('swap', 1, 'none'), ('swap2', 1, 'none'), ('rot3l', 1, 'none'), ('rot3r', 1, 'none'), ('rot4l', 1, 'none'), ('rot5l', 1, 'none'), ('call_constructor', 3, 'npop'), ('call', 3, 'npop'), ('tail_call', 3, 'npop'), ('call_method', 3, 'npop'), ('tail_call_method', 3, 'npop'), ('array_from', 3, 'npop'), ('apply', 3, 'u16'), ('return', 1, 'none'), ('return_undef', 1, 'none'), ('check_ctor_return', 1, 'none'), ('check_ctor', 1, 'none'), ('check_brand', 1, 'none'), ('add_brand', 1, 'none'), ('return_async', 1, 'none'), ('throw', 1, 'none'), ('throw_error', 6, 'atom_u8'), ('eval', 5, 'npop_u16'), ('apply_eval', 3, 'u16'), ('regexp', 1, 'none'), ('get_super', 1, 'none'), ('import', 1, 'none'), ('check_var', 5, 'atom'), ('get_var_undef', 5, 'atom'), ('get_var', 5, 'atom'), ('put_var', 5, 'atom'), ('put_var_init', 5, 'atom'), ('put_var_strict', 5, 'atom'), ('get_ref_value', 1, 'none'), ('put_ref_value', 1, 'none'), ('define_var', 6, 'atom_u8'), ('check_define_var', 6, 'atom_u8'), ('define_func', 6, 'atom_u8'), ('get_field', 5, 'atom'), ('get_field2', 5, 'atom'), ('put_field', 5, 'atom'), ('get_private_field', 1, 'none'), ('put_private_field', 1, 'none'), ('define_private_field', 1, 'none'), ('get_array_el', 1, 'none'), ('get_array_el2', 1, 'none'), ('put_array_el', 1, 'none'), ('get_super_value', 1, 'none'), ('put_super_value', 1, 'none'), ('define_field', 5, 'atom'), ('set_name', 5, 'atom'), ('set_name_computed', 1, 'none'), ('set_proto', 1, 'none'), ('set_home_object', 1, 'none'), ('define_array_el', 1, 'none'), ('append', 1, 'none'), ('copy_data_properties', 2, 'u8'), ('define_method', 6, 'atom_u8'), ('define_method_computed', 2, 'u8'), ('define_class', 6, 'atom_u8'), ('define_class_computed', 6, 'atom_u8'), ('get_loc', 3, 'loc'), ('put_loc', 3, 'loc'), ('set_loc', 3, 'loc'), ('get_arg', 3, 'arg'), ('put_arg', 3, 'arg'), ('set_arg', 3, 'arg'), ('get_var_ref', 3, 'var_ref'), ('put_var_ref', 3, 'var_ref'), ('set_var_ref', 3, 'var_ref'), ('set_loc_uninitialized', 3, 'loc'), ('get_loc_check', 3, 'loc'), ('put_loc_check', 3, 'loc'), ('put_loc_check_init', 3, 'loc'), ('get_loc_checkthis', 3, 'loc'), ('get_var_ref_check', 3, 'var_ref'), ('put_var_ref_check', 3, 'var_ref'), ('put_var_ref_check_init', 3, 'var_ref'), ('close_loc', 3, 'loc'), ('if_false', 5, 'label'), ('if_true', 5, 'label'), ('goto', 5, 'label'), ('catch', 5, 'label'), ('gosub', 5, 'label'), ('ret', 1, 'none'), ('nip_catch', 1, 'none'), ('to_object', 1, 'none'), ('to_propkey', 1, 'none'), ('to_propkey2', 1, 'none'), ('with_get_var', 10, 'atom_label_u8'), ('with_put_var', 10, 'atom_label_u8'), ('with_delete_var', 10, 'atom_label_u8'), ('with_make_ref', 10, 'atom_label_u8'), ('with_get_ref', 10, 'atom_label_u8'), ('with_get_ref_undef', 10, 'atom_label_u8'), ('make_loc_ref', 7, 'atom_u16'), ('make_arg_ref', 7, 'atom_u16'), ('make_var_ref_ref', 7, 'atom_u16'), ('make_var_ref', 5, 'atom'), ('for_in_start', 1, 'none'), ('for_of_start', 1, 'none'), ('for_await_of_start', 1, 'none'), ('for_in_next', 1, 'none'), ('for_of_next', 2, 'u8'), ('iterator_check_object', 1, 'none'), ('iterator_get_value_done', 1, 'none'), ('iterator_close', 1, 'none'), ('iterator_next', 1, 'none'), ('iterator_call', 2, 'u8'), ('initial_yield', 1, 'none'), ('yield', 1, 'none'), ('yield_star', 1, 'none'), ('async_yield_star', 1, 'none'), ('await', 1, 'none'), ('neg', 1, 'none'), ('plus', 1, 'none'), ('dec', 1, 'none'), ('inc', 1, 'none'), ('post_dec', 1, 'none'), ('post_inc', 1, 'none'), ('dec_loc', 2, 'loc8'), ('inc_loc', 2, 'loc8'), ('add_loc', 2, 'loc8'), ('not', 1, 'none'), ('lnot', 1, 'none'), ('typeof', 1, 'none'), ('delete', 1, 'none'), ('delete_var', 5, 'atom'), ('mul', 1, 'none'), ('div', 1, 'none'), ('mod', 1, 'none'), ('add', 1, 'none'), ('sub', 1, 'none'), ('pow', 1, 'none'), ('shl', 1, 'none'), ('sar', 1, 'none'), ('shr', 1, 'none'), ('lt', 1, 'none'), ('lte', 1, 'none'), ('gt', 1, 'none'), ('gte', 1, 'none'), ('instanceof', 1, 'none'), ('in', 1, 'none'), ('eq', 1, 'none'), ('neq', 1, 'none'), ('strict_eq', 1, 'none'), ('strict_neq', 1, 'none'), ('and', 1, 'none'), ('xor', 1, 'none'), ('or', 1, 'none'), ('is_undefined_or_null', 1, 'none'), ('private_in', 1, 'none'), ('mul_pow10', 1, 'none'), ('math_mod', 1, 'none'), ('nop', 1, 'none'), ('push_minus1', 1, 'none_int'), ('push_0', 1, 'none_int'), ('push_1', 1, 'none_int'), ('push_2', 1, 'none_int'), ('push_3', 1, 'none_int'), ('push_4', 1, 'none_int'), ('push_5', 1, 'none_int'), ('push_6', 1, 'none_int'), ('push_7', 1, 'none_int'), ('push_i8', 2, 'i8'), ('push_i16', 3, 'i16'), ('push_const8', 2, 'const8'), ('fclosure8', 2, 'const8'), ('push_empty_string', 1, 'none'), ('get_loc8', 2, 'loc8'), ('put_loc8', 2, 'loc8'), ('set_loc8', 2, 'loc8'), ('get_loc0', 1, 'none_loc'), ('get_loc1', 1, 'none_loc'), ('get_loc2', 1, 'none_loc'), ('get_loc3', 1, 'none_loc'), ('put_loc0', 1, 'none_loc'), ('put_loc1', 1, 'none_loc'), ('put_loc2', 1, 'none_loc'), ('put_loc3', 1, 'none_loc'), ('set_loc0', 1, 'none_loc'), ('set_loc1', 1, 'none_loc'), ('set_loc2', 1, 'none_loc'), ('set_loc3', 1, 'none_loc'), ('get_arg0', 1, 'none_arg'), ('get_arg1', 1, 'none_arg'), ('get_arg2', 1, 'none_arg'), ('get_arg3', 1, 'none_arg'), ('put_arg0', 1, 'none_arg'), ('put_arg1', 1, 'none_arg'), ('put_arg2', 1, 'none_arg'), ('put_arg3', 1, 'none_arg'), ('set_arg0', 1, 'none_arg'), ('set_arg1', 1, 'none_arg'), ('set_arg2', 1, 'none_arg'), ('set_arg3', 1, 'none_arg'), ('get_var_ref0', 1, 'none_var_ref'), ('get_var_ref1', 1, 'none_var_ref'), ('get_var_ref2', 1, 'none_var_ref'), ('get_var_ref3', 1, 'none_var_ref'), ('put_var_ref0', 1, 'none_var_ref'), ('put_var_ref1', 1, 'none_var_ref'), ('put_var_ref2', 1, 'none_var_ref'), ('put_var_ref3', 1, 'none_var_ref'), ('set_var_ref0', 1, 'none_var_ref'), ('set_var_ref1', 1, 'none_var_ref'), ('set_var_ref2', 1, 'none_var_ref'), ('set_var_ref3', 1, 'none_var_ref'), ('get_length', 1, 'none'), ('if_false8', 2, 'label8'), ('if_true8', 2, 'label8'), ('goto8', 2, 'label8'), ('goto16', 3, 'label16'), ('call0', 1, 'npopx'), ('call1', 1, 'npopx'), ('call2', 1, 'npopx'), ('call3', 1, 'npopx'), ('is_undefined', 1, 'none'), ('is_null', 1, 'none'), ('typeof_is_undefined', 1, 'none'), ('typeof_is_function', 1, 'none')]

BELLARD_OPCODE_TABLE = [('invalid', 1, 'none'), ('push_i32', 5, 'i32'), ('push_const', 5, 'const'), ('fclosure', 5, 'const'), ('push_atom_value', 5, 'atom'), ('private_symbol', 5, 'atom'), ('undefined', 1, 'none'), ('null', 1, 'none'), ('push_this', 1, 'none'), ('push_false', 1, 'none'), ('push_true', 1, 'none'), ('object', 1, 'none'), ('special_object', 2, 'u8'), ('rest', 3, 'u16'), ('drop', 1, 'none'), ('nip', 1, 'none'), ('nip1', 1, 'none'), ('dup', 1, 'none'), ('dup1', 1, 'none'), ('dup2', 1, 'none'), ('dup3', 1, 'none'), ('insert2', 1, 'none'), ('insert3', 1, 'none'), ('insert4', 1, 'none'), ('perm3', 1, 'none'), ('perm4', 1, 'none'), ('perm5', 1, 'none'), ('swap', 1, 'none'), ('swap2', 1, 'none'), ('rot3l', 1, 'none'), ('rot3r', 1, 'none'), ('rot4l', 1, 'none'), ('rot5l', 1, 'none'), ('call_constructor', 3, 'npop'), ('call', 3, 'npop'), ('tail_call', 3, 'npop'), ('call_method', 3, 'npop'), ('tail_call_method', 3, 'npop'), ('array_from', 3, 'npop'), ('apply', 3, 'u16'), ('return', 1, 'none'), ('return_undef', 1, 'none'), ('check_ctor_return', 1, 'none'), ('check_ctor', 1, 'none'), ('init_ctor', 1, 'none'), ('check_brand', 1, 'none'), ('add_brand', 1, 'none'), ('return_async', 1, 'none'), ('throw', 1, 'none'), ('throw_error', 6, 'atom_u8'), ('eval', 5, 'npop_u16'), ('apply_eval', 3, 'u16'), ('regexp', 1, 'none'), ('get_super', 1, 'none'), ('import', 1, 'none'), ('get_var_undef', 3, 'var_ref'), ('get_var', 3, 'var_ref'), ('put_var', 3, 'var_ref'), ('put_var_init', 3, 'var_ref'), ('get_ref_value', 1, 'none'), ('put_ref_value', 1, 'none'), ('get_field', 5, 'atom'), ('get_field2', 5, 'atom'), ('put_field', 5, 'atom'), ('get_private_field', 1, 'none'), ('put_private_field', 1, 'none'), ('define_private_field', 1, 'none'), ('get_array_el', 1, 'none'), ('get_array_el2', 1, 'none'), ('get_array_el3', 1, 'none'), ('put_array_el', 1, 'none'), ('get_super_value', 1, 'none'), ('put_super_value', 1, 'none'), ('define_field', 5, 'atom'), ('set_name', 5, 'atom'), ('set_name_computed', 1, 'none'), ('set_proto', 1, 'none'), ('set_home_object', 1, 'none'), ('define_array_el', 1, 'none'), ('append', 1, 'none'), ('copy_data_properties', 2, 'u8'), ('define_method', 6, 'atom_u8'), ('define_method_computed', 2, 'u8'), ('define_class', 6, 'atom_u8'), ('define_class_computed', 6, 'atom_u8'), ('get_loc', 3, 'loc'), ('put_loc', 3, 'loc'), ('set_loc', 3, 'loc'), ('get_arg', 3, 'arg'), ('put_arg', 3, 'arg'), ('set_arg', 3, 'arg'), ('get_var_ref', 3, 'var_ref'), ('put_var_ref', 3, 'var_ref'), ('set_var_ref', 3, 'var_ref'), ('set_loc_uninitialized', 3, 'loc'), ('get_loc_check', 3, 'loc'), ('put_loc_check', 3, 'loc'), ('set_loc_check', 3, 'loc'), ('put_loc_check_init', 3, 'loc'), ('get_loc_checkthis', 3, 'loc'), ('get_var_ref_check', 3, 'var_ref'), ('put_var_ref_check', 3, 'var_ref'), ('put_var_ref_check_init', 3, 'var_ref'), ('close_loc', 3, 'loc'), ('if_false', 5, 'label'), ('if_true', 5, 'label'), ('goto', 5, 'label'), ('catch', 5, 'label'), ('gosub', 5, 'label'), ('ret', 1, 'none'), ('nip_catch', 1, 'none'), ('to_object', 1, 'none'), ('to_propkey', 1, 'none'), ('with_get_var', 10, 'atom_label_u8'), ('with_put_var', 10, 'atom_label_u8'), ('with_delete_var', 10, 'atom_label_u8'), ('with_make_ref', 10, 'atom_label_u8'), ('with_get_ref', 10, 'atom_label_u8'), ('make_loc_ref', 7, 'atom_u16'), ('make_arg_ref', 7, 'atom_u16'), ('make_var_ref_ref', 7, 'atom_u16'), ('make_var_ref', 5, 'atom'), ('for_in_start', 1, 'none'), ('for_of_start', 1, 'none'), ('for_await_of_start', 1, 'none'), ('for_in_next', 1, 'none'), ('for_of_next', 2, 'u8'), ('for_await_of_next', 1, 'none'), ('iterator_check_object', 1, 'none'), ('iterator_get_value_done', 1, 'none'), ('iterator_close', 1, 'none'), ('iterator_next', 1, 'none'), ('iterator_call', 2, 'u8'), ('initial_yield', 1, 'none'), ('yield', 1, 'none'), ('yield_star', 1, 'none'), ('async_yield_star', 1, 'none'), ('await', 1, 'none'), ('neg', 1, 'none'), ('plus', 1, 'none'), ('dec', 1, 'none'), ('inc', 1, 'none'), ('post_dec', 1, 'none'), ('post_inc', 1, 'none'), ('dec_loc', 2, 'loc8'), ('inc_loc', 2, 'loc8'), ('add_loc', 2, 'loc8'), ('not', 1, 'none'), ('lnot', 1, 'none'), ('typeof', 1, 'none'), ('delete', 1, 'none'), ('delete_var', 5, 'atom'), ('mul', 1, 'none'), ('div', 1, 'none'), ('mod', 1, 'none'), ('add', 1, 'none'), ('sub', 1, 'none'), ('pow', 1, 'none'), ('shl', 1, 'none'), ('sar', 1, 'none'), ('shr', 1, 'none'), ('lt', 1, 'none'), ('lte', 1, 'none'), ('gt', 1, 'none'), ('gte', 1, 'none'), ('instanceof', 1, 'none'), ('in', 1, 'none'), ('eq', 1, 'none'), ('neq', 1, 'none'), ('strict_eq', 1, 'none'), ('strict_neq', 1, 'none'), ('and', 1, 'none'), ('xor', 1, 'none'), ('or', 1, 'none'), ('is_undefined_or_null', 1, 'none'), ('private_in', 1, 'none'), ('push_bigint_i32', 5, 'i32'), ('nop', 1, 'none'), ('push_minus1', 1, 'none_int'), ('push_0', 1, 'none_int'), ('push_1', 1, 'none_int'), ('push_2', 1, 'none_int'), ('push_3', 1, 'none_int'), ('push_4', 1, 'none_int'), ('push_5', 1, 'none_int'), ('push_6', 1, 'none_int'), ('push_7', 1, 'none_int'), ('push_i8', 2, 'i8'), ('push_i16', 3, 'i16'), ('push_const8', 2, 'const8'), ('fclosure8', 2, 'const8'), ('push_empty_string', 1, 'none'), ('get_loc8', 2, 'loc8'), ('put_loc8', 2, 'loc8'), ('set_loc8', 2, 'loc8'), ('get_loc0', 1, 'none_loc'), ('get_loc1', 1, 'none_loc'), ('get_loc2', 1, 'none_loc'), ('get_loc3', 1, 'none_loc'), ('put_loc0', 1, 'none_loc'), ('put_loc1', 1, 'none_loc'), ('put_loc2', 1, 'none_loc'), ('put_loc3', 1, 'none_loc'), ('set_loc0', 1, 'none_loc'), ('set_loc1', 1, 'none_loc'), ('set_loc2', 1, 'none_loc'), ('set_loc3', 1, 'none_loc'), ('get_arg0', 1, 'none_arg'), ('get_arg1', 1, 'none_arg'), ('get_arg2', 1, 'none_arg'), ('get_arg3', 1, 'none_arg'), ('put_arg0', 1, 'none_arg'), ('put_arg1', 1, 'none_arg'), ('put_arg2', 1, 'none_arg'), ('put_arg3', 1, 'none_arg'), ('set_arg0', 1, 'none_arg'), ('set_arg1', 1, 'none_arg'), ('set_arg2', 1, 'none_arg'), ('set_arg3', 1, 'none_arg'), ('get_var_ref0', 1, 'none_var_ref'), ('get_var_ref1', 1, 'none_var_ref'), ('get_var_ref2', 1, 'none_var_ref'), ('get_var_ref3', 1, 'none_var_ref'), ('put_var_ref0', 1, 'none_var_ref'), ('put_var_ref1', 1, 'none_var_ref'), ('put_var_ref2', 1, 'none_var_ref'), ('put_var_ref3', 1, 'none_var_ref'), ('set_var_ref0', 1, 'none_var_ref'), ('set_var_ref1', 1, 'none_var_ref'), ('set_var_ref2', 1, 'none_var_ref'), ('set_var_ref3', 1, 'none_var_ref'), ('get_length', 1, 'none'), ('if_false8', 2, 'label8'), ('if_true8', 2, 'label8'), ('goto8', 2, 'label8'), ('goto16', 3, 'label16'), ('call0', 1, 'npopx'), ('call1', 1, 'npopx'), ('call2', 1, 'npopx'), ('call3', 1, 'npopx'), ('is_undefined', 1, 'none'), ('is_null', 1, 'none'), ('typeof_is_undefined', 1, 'none'), ('typeof_is_function', 1, 'none')]

NG_OPCODE_TABLE = [('invalid', 1, 'none'), ('push_i32', 5, 'i32'), ('push_const', 5, 'const'), ('fclosure', 5, 'const'), ('push_atom_value', 5, 'atom'), ('private_symbol', 5, 'atom'), ('undefined', 1, 'none'), ('null', 1, 'none'), ('push_this', 1, 'none'), ('push_false', 1, 'none'), ('push_true', 1, 'none'), ('object', 1, 'none'), ('special_object', 2, 'u8'), ('rest', 3, 'u16'), ('drop', 1, 'none'), ('nip', 1, 'none'), ('nip1', 1, 'none'), ('dup', 1, 'none'), ('dup1', 1, 'none'), ('dup2', 1, 'none'), ('dup3', 1, 'none'), ('insert2', 1, 'none'), ('insert3', 1, 'none'), ('insert4', 1, 'none'), ('perm3', 1, 'none'), ('perm4', 1, 'none'), ('perm5', 1, 'none'), ('swap', 1, 'none'), ('swap2', 1, 'none'), ('rot3l', 1, 'none'), ('rot3r', 1, 'none'), ('rot4l', 1, 'none'), ('rot5l', 1, 'none'), ('call_constructor', 3, 'npop'), ('call', 3, 'npop'), ('tail_call', 3, 'npop'), ('call_method', 3, 'npop'), ('tail_call_method', 3, 'npop'), ('array_from', 3, 'npop'), ('apply', 3, 'u16'), ('return', 1, 'none'), ('return_undef', 1, 'none'), ('check_ctor_return', 1, 'none'), ('check_ctor', 1, 'none'), ('init_ctor', 1, 'none'), ('check_brand', 1, 'none'), ('add_brand', 1, 'none'), ('return_async', 1, 'none'), ('throw', 1, 'none'), ('throw_error', 6, 'atom_u8'), ('eval', 5, 'npop_u16'), ('apply_eval', 3, 'u16'), ('regexp', 1, 'none'), ('get_super', 1, 'none'), ('import', 1, 'none'), ('get_var_undef', 5, 'atom'), ('get_var', 5, 'atom'), ('put_var', 5, 'atom'), ('put_var_init', 5, 'atom'), ('get_ref_value', 1, 'none'), ('put_ref_value', 1, 'none'), ('define_var', 6, 'atom_u8'), ('check_define_var', 6, 'atom_u8'), ('define_func', 6, 'atom_u8'), ('get_field', 5, 'atom'), ('get_field2', 5, 'atom'), ('put_field', 5, 'atom'), ('get_private_field', 1, 'none'), ('put_private_field', 1, 'none'), ('define_private_field', 1, 'none'), ('get_array_el', 1, 'none'), ('get_array_el2', 1, 'none'), ('put_array_el', 1, 'none'), ('get_super_value', 1, 'none'), ('put_super_value', 1, 'none'), ('define_field', 5, 'atom'), ('set_name', 5, 'atom'), ('set_name_computed', 1, 'none'), ('set_proto', 1, 'none'), ('set_home_object', 1, 'none'), ('define_array_el', 1, 'none'), ('append', 1, 'none'), ('copy_data_properties', 2, 'u8'), ('define_method', 6, 'atom_u8'), ('define_method_computed', 2, 'u8'), ('define_class', 6, 'atom_u8'), ('define_class_computed', 6, 'atom_u8'), ('get_loc', 3, 'loc'), ('put_loc', 3, 'loc'), ('set_loc', 3, 'loc'), ('get_arg', 3, 'arg'), ('put_arg', 3, 'arg'), ('set_arg', 3, 'arg'), ('get_var_ref', 3, 'var_ref'), ('put_var_ref', 3, 'var_ref'), ('set_var_ref', 3, 'var_ref'), ('set_loc_uninitialized', 3, 'loc'), ('get_loc_check', 3, 'loc'), ('put_loc_check', 3, 'loc'), ('put_loc_check_init', 3, 'loc'), ('get_var_ref_check', 3, 'var_ref'), ('put_var_ref_check', 3, 'var_ref'), ('put_var_ref_check_init', 3, 'var_ref'), ('close_loc', 3, 'loc'), ('if_false', 5, 'label'), ('if_true', 5, 'label'), ('goto', 5, 'label'), ('catch', 5, 'label'), ('gosub', 5, 'label'), ('ret', 1, 'none'), ('nip_catch', 1, 'none'), ('to_object', 1, 'none'), ('to_propkey', 1, 'none'), ('to_propkey2', 1, 'none'), ('with_get_var', 10, 'atom_label_u8'), ('with_put_var', 10, 'atom_label_u8'), ('with_delete_var', 10, 'atom_label_u8'), ('with_make_ref', 10, 'atom_label_u8'), ('with_get_ref', 10, 'atom_label_u8'), ('with_get_ref_undef', 10, 'atom_label_u8'), ('make_loc_ref', 7, 'atom_u16'), ('make_arg_ref', 7, 'atom_u16'), ('make_var_ref_ref', 7, 'atom_u16'), ('make_var_ref', 5, 'atom'), ('for_in_start', 1, 'none'), ('for_of_start', 1, 'none'), ('for_await_of_start', 1, 'none'), ('for_in_next', 1, 'none'), ('for_of_next', 2, 'u8'), ('iterator_check_object', 1, 'none'), ('iterator_get_value_done', 1, 'none'), ('iterator_close', 1, 'none'), ('iterator_next', 1, 'none'), ('iterator_call', 2, 'u8'), ('initial_yield', 1, 'none'), ('yield', 1, 'none'), ('yield_star', 1, 'none'), ('async_yield_star', 1, 'none'), ('await', 1, 'none'), ('neg', 1, 'none'), ('plus', 1, 'none'), ('dec', 1, 'none'), ('inc', 1, 'none'), ('post_dec', 1, 'none'), ('post_inc', 1, 'none'), ('dec_loc', 2, 'loc8'), ('inc_loc', 2, 'loc8'), ('add_loc', 2, 'loc8'), ('not', 1, 'none'), ('lnot', 1, 'none'), ('typeof', 1, 'none'), ('delete', 1, 'none'), ('delete_var', 5, 'atom'), ('mul', 1, 'none'), ('div', 1, 'none'), ('mod', 1, 'none'), ('add', 1, 'none'), ('sub', 1, 'none'), ('shl', 1, 'none'), ('sar', 1, 'none'), ('shr', 1, 'none'), ('and', 1, 'none'), ('xor', 1, 'none'), ('or', 1, 'none'), ('pow', 1, 'none'), ('lt', 1, 'none'), ('lte', 1, 'none'), ('gt', 1, 'none'), ('gte', 1, 'none'), ('instanceof', 1, 'none'), ('in', 1, 'none'), ('eq', 1, 'none'), ('neq', 1, 'none'), ('strict_eq', 1, 'none'), ('strict_neq', 1, 'none'), ('is_undefined_or_null', 1, 'none'), ('private_in', 1, 'none'), ('push_bigint_i32', 5, 'i32'), ('nop', 1, 'none'), ('push_minus1', 1, 'none_int'), ('push_0', 1, 'none_int'), ('push_1', 1, 'none_int'), ('push_2', 1, 'none_int'), ('push_3', 1, 'none_int'), ('push_4', 1, 'none_int'), ('push_5', 1, 'none_int'), ('push_6', 1, 'none_int'), ('push_7', 1, 'none_int'), ('push_i8', 2, 'i8'), ('push_i16', 3, 'i16'), ('push_const8', 2, 'const8'), ('fclosure8', 2, 'const8'), ('push_empty_string', 1, 'none'), ('get_loc8', 2, 'loc8'), ('put_loc8', 2, 'loc8'), ('set_loc8', 2, 'loc8'), ('get_loc0_loc1', 1, 'none_loc'), ('get_loc0', 1, 'none_loc'), ('get_loc1', 1, 'none_loc'), ('get_loc2', 1, 'none_loc'), ('get_loc3', 1, 'none_loc'), ('put_loc0', 1, 'none_loc'), ('put_loc1', 1, 'none_loc'), ('put_loc2', 1, 'none_loc'), ('put_loc3', 1, 'none_loc'), ('set_loc0', 1, 'none_loc'), ('set_loc1', 1, 'none_loc'), ('set_loc2', 1, 'none_loc'), ('set_loc3', 1, 'none_loc'), ('get_arg0', 1, 'none_arg'), ('get_arg1', 1, 'none_arg'), ('get_arg2', 1, 'none_arg'), ('get_arg3', 1, 'none_arg'), ('put_arg0', 1, 'none_arg'), ('put_arg1', 1, 'none_arg'), ('put_arg2', 1, 'none_arg'), ('put_arg3', 1, 'none_arg'), ('set_arg0', 1, 'none_arg'), ('set_arg1', 1, 'none_arg'), ('set_arg2', 1, 'none_arg'), ('set_arg3', 1, 'none_arg'), ('get_var_ref0', 1, 'none_var_ref'), ('get_var_ref1', 1, 'none_var_ref'), ('get_var_ref2', 1, 'none_var_ref'), ('get_var_ref3', 1, 'none_var_ref'), ('put_var_ref0', 1, 'none_var_ref'), ('put_var_ref1', 1, 'none_var_ref'), ('put_var_ref2', 1, 'none_var_ref'), ('put_var_ref3', 1, 'none_var_ref'), ('set_var_ref0', 1, 'none_var_ref'), ('set_var_ref1', 1, 'none_var_ref'), ('set_var_ref2', 1, 'none_var_ref'), ('set_var_ref3', 1, 'none_var_ref'), ('get_length', 1, 'none'), ('if_false8', 2, 'label8'), ('if_true8', 2, 'label8'), ('goto8', 2, 'label8'), ('goto16', 3, 'label16'), ('call0', 1, 'npopx'), ('call1', 1, 'npopx'), ('call2', 1, 'npopx'), ('call3', 1, 'npopx'), ('is_undefined', 1, 'none'), ('is_null', 1, 'none'), ('typeof_is_undefined', 1, 'none'), ('typeof_is_function', 1, 'none')]

# ── BUILT-IN ATOM TABLES ──────────────────────────────────────────────────

FRIDA_ATOMS = ['<null>', 'null', 'false', 'true', 'if', 'else', 'return', 'var', 'this', 'delete', 'void', 'typeof', 'new', 'in', 'instanceof', 'do', 'while', 'for', 'break', 'continue', 'switch', 'case', 'default', 'throw', 'try', 'catch', 'finally', 'function', 'debugger', 'with', 'class', 'const', 'enum', 'export', 'extends', 'import', 'super', 'implements', 'interface', 'let', 'package', 'private', 'protected', 'public', 'static', 'yield', 'await', '', 'length', 'fileName', 'lineNumber', 'message', 'cause', 'errors', 'stack', 'prepareStackTrace', 'name', 'toString', 'toLocaleString', 'valueOf', 'eval', 'prototype', 'constructor', 'configurable', 'writable', 'enumerable', 'value', 'get', 'set', 'of', '__proto__', 'undefined', 'number', 'boolean', 'string', 'object', 'symbol', 'integer', 'unknown', 'arguments', 'callee', 'caller', '<eval>', '<ret>', '<var>', '<arg_var>', '<with>', 'lastIndex', 'target', 'index', 'input', 'defineProperties', 'apply', 'join', 'concat', 'split', 'construct', 'getPrototypeOf', 'setPrototypeOf', 'isExtensible', 'preventExtensions', 'has', 'deleteProperty', 'defineProperty', 'getOwnPropertyDescriptor', 'ownKeys', 'add', 'done', 'next', 'values', 'source', 'flags', 'global', 'unicode', 'raw', 'new.target', 'this.active_func', '<home_object>', '<computed_field>', '<static_computed_field>', '<class_fields_init>', '<brand>', '#constructor', 'as', 'from', 'meta', '*default*', '*', 'Module', 'then', 'resolve', 'reject', 'promise', 'proxy', 'revoke', 'async', 'exec', 'groups', 'indices', 'status', 'reason', 'globalThis', 'bigint', 'bigfloat', 'bigdecimal', 'roundingMode', 'maximumSignificantDigits', 'maximumFractionDigits', 'not-equal', 'timed-out', 'ok', 'toJSON', 'Object', 'Array', 'Error', 'Number', 'String', 'Boolean', 'Symbol', 'Arguments', 'Math', 'JSON', 'Date', 'Function', 'GeneratorFunction', 'ForInIterator', 'RegExp', 'ArrayBuffer', 'SharedArrayBuffer', 'Uint8ClampedArray', 'Int8Array', 'Uint8Array', 'Int16Array', 'Uint16Array', 'Int32Array', 'Uint32Array', 'BigInt64Array', 'BigUint64Array', 'Float32Array', 'Float64Array', 'DataView', 'BigInt', 'BigFloat', 'BigFloatEnv', 'BigDecimal', 'OperatorSet', 'Operators', 'Map', 'Set', 'WeakMap', 'WeakSet', 'Map Iterator', 'Set Iterator', 'Array Iterator', 'String Iterator', 'RegExp String Iterator', 'Generator', 'Proxy', 'Promise', 'PromiseResolveFunction', 'PromiseRejectFunction', 'AsyncFunction', 'AsyncFunctionResolve', 'AsyncFunctionReject', 'AsyncGeneratorFunction', 'AsyncGenerator', 'EvalError', 'RangeError', 'ReferenceError', 'SyntaxError', 'TypeError', 'URIError', 'InternalError', '<brand>', 'Symbol.toPrimitive', 'Symbol.iterator', 'Symbol.match', 'Symbol.matchAll', 'Symbol.replace', 'Symbol.search', 'Symbol.split', 'Symbol.toStringTag', 'Symbol.isConcatSpreadable', 'Symbol.hasInstance', 'Symbol.species', 'Symbol.unscopables', 'Symbol.asyncIterator', 'Symbol.operatorSet']

BELLARD_ATOMS = ['<null>', 'null', 'false', 'true', 'if', 'else', 'return', 'var', 'this', 'delete', 'void', 'typeof', 'new', 'in', 'instanceof', 'do', 'while', 'for', 'break', 'continue', 'switch', 'case', 'default', 'throw', 'try', 'catch', 'finally', 'function', 'debugger', 'with', 'class', 'const', 'enum', 'export', 'extends', 'import', 'super', 'implements', 'interface', 'let', 'package', 'private', 'protected', 'public', 'static', 'yield', 'await', '', 'keys', 'size', 'length', 'fileName', 'lineNumber', 'columnNumber', 'message', 'cause', 'errors', 'stack', 'name', 'toString', 'toLocaleString', 'valueOf', 'eval', 'prototype', 'constructor', 'configurable', 'writable', 'enumerable', 'value', 'get', 'set', 'of', '__proto__', 'undefined', 'number', 'boolean', 'string', 'object', 'symbol', 'integer', 'unknown', 'arguments', 'callee', 'caller', '<eval>', '<ret>', '<var>', '<arg_var>', '<with>', 'lastIndex', 'target', 'index', 'input', 'defineProperties', 'apply', 'join', 'concat', 'split', 'construct', 'getPrototypeOf', 'setPrototypeOf', 'isExtensible', 'preventExtensions', 'has', 'deleteProperty', 'defineProperty', 'getOwnPropertyDescriptor', 'ownKeys', 'add', 'done', 'next', 'values', 'source', 'flags', 'global', 'unicode', 'raw', 'rawJSON', 'new.target', 'this.active_func', '<home_object>', '<computed_field>', '<static_computed_field>', '<class_fields_init>', '<brand>', '#constructor', 'as', 'from', 'meta', '*default*', '*', 'Module', 'then', 'resolve', 'reject', 'promise', 'proxy', 'revoke', 'async', 'exec', 'groups', 'indices', 'status', 'reason', 'globalThis', 'bigint', '-0', 'Infinity', '-Infinity', 'NaN', 'hasIndices', 'ignoreCase', 'multiline', 'dotAll', 'sticky', 'unicodeSets', 'not-equal', 'timed-out', 'ok', 'toJSON', 'maxByteLength', 'Object', 'Array', 'Error', 'Number', 'String', 'Boolean', 'Symbol', 'Arguments', 'Math', 'JSON', 'Date', 'Function', 'GeneratorFunction', 'ForInIterator', 'RegExp', 'ArrayBuffer', 'SharedArrayBuffer', 'Uint8ClampedArray', 'Int8Array', 'Uint8Array', 'Int16Array', 'Uint16Array', 'Int32Array', 'Uint32Array', 'BigInt64Array', 'BigUint64Array', 'Float16Array', 'Float32Array', 'Float64Array', 'DataView', 'BigInt', 'WeakRef', 'FinalizationRegistry', 'Map', 'Set', 'WeakMap', 'WeakSet', 'Iterator', 'Iterator Helper', 'Iterator Concat', 'Iterator Wrap', 'Map Iterator', 'Set Iterator', 'Array Iterator', 'String Iterator', 'RegExp String Iterator', 'Generator', 'Proxy', 'Promise', 'PromiseResolveFunction', 'PromiseRejectFunction', 'AsyncFunction', 'AsyncFunctionResolve', 'AsyncFunctionReject', 'AsyncGeneratorFunction', 'AsyncGenerator', 'EvalError', 'RangeError', 'ReferenceError', 'SyntaxError', 'TypeError', 'URIError', 'InternalError', 'AggregateError', '<brand>', 'Symbol.toPrimitive', 'Symbol.iterator', 'Symbol.match', 'Symbol.matchAll', 'Symbol.replace', 'Symbol.search', 'Symbol.split', 'Symbol.toStringTag', 'Symbol.isConcatSpreadable', 'Symbol.hasInstance', 'Symbol.species', 'Symbol.unscopables', 'Symbol.asyncIterator']

NG_ATOMS = ['<null>', 'null', 'false', 'true', 'if', 'else', 'return', 'var', 'this', 'delete', 'void', 'typeof', 'new', 'in', 'instanceof', 'do', 'while', 'for', 'break', 'continue', 'switch', 'case', 'default', 'throw', 'try', 'catch', 'finally', 'function', 'debugger', 'with', 'class', 'const', 'enum', 'export', 'extends', 'import', 'super', 'implements', 'interface', 'let', 'package', 'private', 'protected', 'public', 'static', 'yield', 'await', '', 'keys', 'size', 'length', 'message', 'cause', 'errors', 'stack', 'name', 'toString', 'toLocaleString', 'valueOf', 'eval', 'prototype', 'constructor', 'configurable', 'writable', 'enumerable', 'value', 'get', 'set', 'of', '__proto__', 'undefined', 'number', 'boolean', 'string', 'object', 'symbol', 'integer', 'unknown', 'arguments', 'callee', 'caller', '<eval>', '<ret>', '<var>', '<arg_var>', '<with>', 'lastIndex', 'target', 'index', 'input', 'defineProperties', 'apply', 'join', 'concat', 'split', 'construct', 'getPrototypeOf', 'setPrototypeOf', 'isExtensible', 'preventExtensions', 'has', 'deleteProperty', 'defineProperty', 'getOwnPropertyDescriptor', 'ownKeys', 'add', 'done', 'next', 'values', 'source', 'flags', 'global', 'unicode', 'raw', 'new.target', 'this.active_func', '<home_object>', '<computed_field>', '<static_computed_field>', '<class_fields_init>', '<brand>', '#constructor', 'as', 'from', 'fromAsync', 'meta', '*default*', '*', 'Module', 'then', 'resolve', 'reject', 'promise', 'proxy', 'revoke', 'async', 'exec', 'groups', 'indices', 'status', 'reason', 'globalThis', 'bigint', 'not-equal', 'timed-out', 'ok', 'toJSON', 'maxByteLength', 'zip', 'zipKeyed', 'Object', 'Array', 'Error', 'Number', 'String', 'Boolean', 'Symbol', 'Arguments', 'Math', 'JSON', 'Date', 'Function', 'GeneratorFunction', 'ForInIterator', 'RegExp', 'ArrayBuffer', 'SharedArrayBuffer', 'Uint8ClampedArray', 'Int8Array', 'Uint8Array', 'Int16Array', 'Uint16Array', 'Int32Array', 'Uint32Array', 'BigInt64Array', 'BigUint64Array', 'Float16Array', 'Float32Array', 'Float64Array', 'DataView', 'BigInt', 'WeakRef', 'FinalizationRegistry', 'Map', 'Set', 'WeakMap', 'WeakSet', 'Iterator', 'Iterator Concat', 'Iterator Helper', 'Iterator Wrap', 'Map Iterator', 'Set Iterator', 'Array Iterator', 'String Iterator', 'RegExp String Iterator', 'Generator', 'Proxy', 'Promise', 'PromiseResolveFunction', 'PromiseRejectFunction', 'AsyncFunction', 'AsyncFunctionResolve', 'AsyncFunctionReject', 'AsyncGeneratorFunction', 'AsyncGenerator', 'EvalError', 'RangeError', 'ReferenceError', 'SyntaxError', 'TypeError', 'URIError', 'InternalError', 'DOMException', 'CallSite', '<brand>', 'Symbol.toPrimitive', 'Symbol.iterator', 'Symbol.match', 'Symbol.matchAll', 'Symbol.replace', 'Symbol.search', 'Symbol.split', 'Symbol.toStringTag', 'Symbol.isConcatSpreadable', 'Symbol.hasInstance', 'Symbol.species', 'Symbol.unscopables', 'Symbol.asyncIterator']



# ── VERSION CONFIG INSTANCES ──────────────────────────────────────────────

def make_opcode_map(table):
    return {i: op for i, op in enumerate(table)}

# Frida v2 (CONFIG_BIGNUM): BC_TAG_FUNCTION_BYTECODE = 14 (0x0E)
# because BigFloat(11) + BigDecimal(12) shift it
FRIDA_V2 = VersionConfig(
    name='frida_v2',
    bc_tag_func=0x0E,
    first_atom=228,
    has_var_ref_count=False,
    vardef_uses_scope_level=True,
    opcode_table=make_opcode_map(FRIDA_OPCODE_TABLE),
    atom_table=FRIDA_ATOMS,
)

# Bellard upstream v5: BC_TAG_FUNCTION_BYTECODE = 12 (0x0C)
# NULL=1 UNDEF=2 FALSE=3 TRUE=4 INT32=5 FLOAT64=6 STRING=7 OBJ=8 ARR=9 BIGINT=10 TEMPLATE=11 FUNC=12
BELLARD_V5 = VersionConfig(
    name='bellard_v5',
    bc_tag_func=0x0C,
    first_atom=239,
    has_var_ref_count=True,
    vardef_uses_scope_level=False,     # uses scope_next + var_ref_idx
    opcode_table=make_opcode_map(BELLARD_OPCODE_TABLE),
    atom_table=BELLARD_ATOMS,
)

# Bellard v1 (old, no bignum): same opcode table as v5, same BC_TAG_FUNC
# but slightly fewer atoms (Bellard added atoms over time)
# Actually v1 has no push_bigint_i32 — it uses the same table minus that
# For simplicity, use bellard table (the BigInt opcode just won't appear)
BELLARD_V1 = VersionConfig(
    name='bellard_v1',
    bc_tag_func=0x0C,
    first_atom=239,
    has_var_ref_count=True,
    vardef_uses_scope_level=False,
    opcode_table=make_opcode_map(BELLARD_OPCODE_TABLE),
    atom_table=BELLARD_ATOMS,
)

# QuickJS-NG v24: BC_TAG_FUNCTION_BYTECODE = 12 (no BigFloat/BigDecimal)
# Uses scope_level in vardefs (like Frida) but has var_ref_count
# NG also has 'is_strict_mode' byte instead of 'js_mode'
NG_V24 = VersionConfig(
    name='ng_v24',
    bc_tag_func=0x0C,
    first_atom=229,
    has_var_ref_count=True,
    vardef_uses_scope_level=True,     # uses scope_level like Frida
    opcode_table=make_opcode_map(NG_OPCODE_TABLE),
    atom_table=NG_ATOMS,
)

# Big-endian variants
FRIDA_V2_BE  = VersionConfig('frida_v2_be',   0x0E, 228, False, True,  make_opcode_map(FRIDA_OPCODE_TABLE),   FRIDA_ATOMS,   big_endian=True)
BELLARD_V5_BE = VersionConfig('bellard_v5_be', 0x0C, 239, True,  False, make_opcode_map(BELLARD_OPCODE_TABLE), BELLARD_ATOMS, big_endian=True)
BELLARD_V1_BE = VersionConfig('bellard_v1_be', 0x0C, 239, True,  False, make_opcode_map(BELLARD_OPCODE_TABLE), BELLARD_ATOMS, big_endian=True)


VERSION_REGISTRY = {
    0x01: BELLARD_V1,
    0x02: FRIDA_V2,
    0x05: BELLARD_V5,
    0x18: NG_V24,          # 24 = 0x18
    0x41: BELLARD_V1_BE,
    0x42: FRIDA_V2_BE,
    0x45: BELLARD_V5_BE,
}

def get_version_config(version_byte):
    """Get VersionConfig for a given BC_VERSION byte. Returns None if unknown."""
    return VERSION_REGISTRY.get(version_byte)
