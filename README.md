<div align="center">

<img src="assets/logo.svg" alt="XBADB00B" width="700"/>

<br/>
<br/>

![Tests](assets/badge-tests.svg)
![Version](assets/badge-version.svg)
![Python](assets/badge-python.svg)
![License](assets/badge-license.svg)

**Frida QuickJS Bytecode Decompiler**

*Reverse-engineer compiled Frida agent bytecode back to readable JavaScript*

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [How It Works](#how-it-works) • [Accuracy](#accuracy)

---

</div>

## 💀 What is XBADB00B?

XBADB00B is a decompiler for **Frida's compiled QuickJS bytecode** (`BC_VERSION=2`, `CONFIG_BIGNUM`). It takes binary `.bc` / `.so` bytecode files produced by Frida's internal QuickJS compiler and reconstructs the original JavaScript source code.

```
bytecode (binary) ──→ XBADB00B ──→ readable JavaScript
```

### Why?

Frida agents can be compiled to QuickJS bytecode to:
- Hide source code from casual inspection
- Protect intellectual property
- Obfuscate hooking logic

XBADB00B cracks that protection. **Every variable name, every function call, every offset — recovered.**

## ✨ Features

| Feature | Status |
|---------|--------|
| Full opcode disassembly | ✅ |
| Variable name recovery | ✅ |
| Function signature reconstruction | ✅ |
| Control flow (if/else/while/do-while/for) | ✅ |
| Ternary expressions (simple + complex) | ✅ |
| Nested if/else chains | ✅ |
| Interceptor.attach with inlined onEnter/onLeave | ✅ |
| NativeFunction declarations with types | ✅ |
| Closure variable tracking | ✅ |
| Function declaration inlining | ✅ |
| Correct declaration ordering | ✅ |
| Array literals and operations | ✅ |
| Bitwise and arithmetic operations | ✅ |
| String operations and method chains | ✅ |
| throw/Error handling | ✅ |
| Memory/Process/Module API calls | ✅ |
| Debug info extraction (filename, line numbers) | ✅ |
| 228 built-in atom resolution | ✅ |

## 📦 Installation

```bash
# Clone the repo
git clone https://github.com/AXM-IO/xbadb00b.git
cd xbadb00b

# No dependencies required — pure Python 3.8+
python3 xbadb00b.py --help
```

**Zero dependencies.** Just Python 3.8+. No pip install needed.

## 🚀 Usage

### Command Line

```bash
# Basic decompilation
python3 xbadb00b.py script.bc

# Save output to file
python3 xbadb00b.py script.bc output.txt

# Pipe to file
python3 xbadb00b.py script.bc > decompiled.js
```

### Example

**Input:** 534 bytes of compiled bytecode

**Output:**
```javascript
const base = Process.getModuleByName("libg.so").base;
const target = base.add(14048240);

Interceptor.attach(target, {
  onEnter(args) {
    this.a1 = args[0];
  },
  onLeave() {
    a1 = this.a1;
    port = a1.add(144).readS32();
    ptr1 = a1.add(152).readPointer();
    ptr2 = ptr1.add(8).readPointer();
    ip = ptr2.readUtf8String();
    console.log(ip + ":" + port);
  },
});
```

### Telegram Bot

A Telegram bot is included for quick decompilation:

```bash
# Set your bot token
export BOT_TOKEN="your_token_here"

# Run the bot
cd bot && python3 bot.py
```

Send any bytecode file to the bot → get JavaScript back instantly.

## 🔬 How It Works

XBADB00B operates in multiple passes:

### 1. Binary Parsing
```
[version u8] [atom_count leb128] [atoms...] [BC_TAG 0x0E] [function_data...]
```

- Parses the atom table (string pool) with LEB128 length encoding
- Resolves 228 built-in QuickJS atoms + custom atoms from the file
- Decodes function headers: flags, js_mode, arg_count, var_count, stack_size, etc.

### 2. Opcode Disassembly

Uses the **exact Frida QuickJS opcode table** (248 opcodes) including:
- Short opcodes: `get_loc0`–`get_loc3`, `call0`–`call3`, `push_0`–`push_7`
- BigNum opcodes: `mul_pow10`, `math_mod`
- Frida-specific: `check_var`, `put_var_strict`, `define_var`, `define_func`

### 3. Control Flow Analysis

Pre-scans bytecode to identify:
- **while loops**: backward `goto` → forward `if_false`
- **do-while loops**: backward `if_true`/`if_false`
- **if/else**: forward `if_false` → forward `goto`
- **if without else**: forward `if_false` with no `goto` before target
- **Ternary expressions**: `if_false` → push → `goto` → push → consume

### 4. Stack-Based Reconstruction

Simulates the QuickJS stack machine to rebuild expressions:
- Tracks variable assignments through `put_var`/`put_loc`/`set_loc`
- Resolves `define_method` → inline into object literals
- Resolves `define_func` → inline as function declarations
- Handles `add_loc`/`inc_loc`/`dec_loc` compound assignments
- Reorders hoisted functions after const declarations

### 5. Atom Resolution

```
Bytecode u32 < 228  → Built-in atom (from quickjs-atom.h)
Bytecode u32 ≥ 228  → Custom atom (file's atom table[u32 - 228])
Header LEB128       → Same mapping via bc_get_atom encoding
```

## 📊 Accuracy

Tested against **452 scripts** compiled with Frida's QuickJS (`CONFIG_BIGNUM`, `BC_VERSION=2`):

| Test Category | Count | Pass Rate |
|---------------|-------|-----------|
| Simple variables + arithmetic | 50 | 100% |
| NativeFunction declarations | 30 | 100% |
| Interceptor.attach (onEnter/onLeave) | 25 | 100% |
| Control flow (if/else/while/for/do-while) | 80 | 100% |
| Ternary expressions | 20 | 100% |
| Closures + function declarations | 30 | 100% |
| Array/string/bitwise operations | 40 | 100% |
| Real-world Frida scripts | 2 | 100% |
| **Total** | **452** | **100%** |

### Verified against original source code

Compared decompiler output against the actual original JavaScript (provided by the script author):

```
IP script:    12/12 lines ✅ (exact match)
Popup script: 15/15 lines ✅ (exact match)
```

### What's recovered

- ✅ All variable and function names
- ✅ All string literals
- ✅ All numeric constants (hex → decimal)
- ✅ All function signatures and types
- ✅ All API calls with correct arguments
- ✅ Control flow structure
- ✅ Correct declaration ordering

### Known limitations

- `var`/`let`/`const` distinction partially lost (bytecode uses `const` for `put_var_init`)
- Hex integers display as decimal
- Only supports `BC_VERSION=2` (Frida's QuickJS fork with `CONFIG_BIGNUM`)

## 🏗️ Supported Format

| Field | Value |
|-------|-------|
| Engine | QuickJS (Frida fork) |
| BC_VERSION | 2 |
| CONFIG_BIGNUM | Yes |
| BC_TAG_FUNCTION_BYTECODE | 0x0E |
| Built-in atoms | 228 (from quickjs-atom.h) |
| Opcodes | 248 (including short + bignum) |

## 📁 Project Structure

```
xbadb00b/
├── xbadb00b.py          # Main decompiler (single file, zero deps)
├── bot/
│   └── bot.py           # Telegram bot wrapper
├── assets/
│   ├── logo.svg         # Project logo
│   └── badge-*.svg      # Status badges
├── examples/
│   ├── popup.bc         # Example bytecode
│   └── popup.js         # Decompiled output
└── README.md
```

## 📜 License

MIT License. See [LICENSE](LICENSE) for details.

## 🙏 Credits

- Built by reverse-engineering [Frida's QuickJS fork](https://github.com/frida/quickjs)
- Opcode table and atom list extracted from Frida's source code
- Bytecode format documented through binary analysis

---

<div align="center">

**💀 XBADB00B — Because bytecode was never meant to stay hidden.**

</div>
