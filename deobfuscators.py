import re
import codecs
import base64

def beautify_lua(code: str) -> str:
    """
    Applies basic formatting and indentation to Lua code.
    This is a preliminary step for all deobfuscation efforts.
    """
    indent_level = 0
    formatted_lines = []
    lines = code.split('\n')
    for line in lines:
        stripped_line = line.strip()
        if not stripped_line:
            formatted_lines.append("")
            continue

        if stripped_line.startswith("end") or stripped_line.startswith("until") or \
           stripped_line.startswith("else") or stripped_line.startswith("elseif"):
            indent_level = max(0, indent_level - 1)

        formatted_lines.append("    " * indent_level + stripped_line)

        if stripped_line.endswith("do") or stripped_line.endswith("then") or \
           stripped_line.startswith("function") or stripped_line.startswith("repeat"):
            indent_level += 1
        elif stripped_line.startswith("else"):
            indent_level += 1

    return "\n".join(formatted_lines)

def deobf_constant_dump(code: str) -> str:
    """
    Extracts and lists potential constants and function definitions from the Lua code.
    This is not full deobfuscation, but a way to inspect hidden values.
    """
    output = ["--- Constant and Function Dump ---"]

    string_constants = re.findall(r'local \w+\s*=\s*(".*?"|".*?")', code)
    if string_constants:
        output.append("\n**String Constants Found:**")
        for const in sorted(list(set(string_constants))):
            output.append(f"- {const}")

    numeric_constants = re.findall(r'local \w+\s*=\s*(\d+(\.\d*)?)', code)
    if numeric_constants:
        output.append("\n**Numeric Constants Found:**")
        for const, _ in sorted(list(set(numeric_constants))):
            output.append(f"- {const}")

    function_defs = re.findall(r'(local\s+)?function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(.*?\)', code)
    if function_defs:
        output.append("\n**Function Definitions Found:**")
        for local_keyword, func_name in sorted(list(set(function_defs))):
            output.append(f"- {local_keyword or ''}function {func_name}")

    if len(output) == 1:
        output.append("\nNo obvious constants or functions found with basic parsing.")

    output.append("\n--- Original Code (formatted) ---")
    output.append(beautify_lua(code))

    return "\n".join(output)

# --- Helper Functions for Deobfuscation Techniques ---

def _unescape_lua_string(text: str) -> str:
    """
    Decodes Lua-style escape sequences in a string literal.
    Handles \xXX, \u{XXXX}, \DDD (octal), and other common escapes.
    """
    try:
        temp_text = text.replace(r'\u{', r'\u').replace(r'}', '')
        decoded_bytes = temp_text.encode('latin1').decode('unicode_escape').encode('latin1')
        return decoded_bytes.decode('utf-8', errors='ignore')
    except Exception:
        return text

def _decode_hex_strings(code: str) -> str:
    """Decodes common hex-encoded string patterns (e.g., \xXX, %xXX)"""
    def replace_hex(match):
        hex_str = match.group(1) or match.group(2)
        try:
            return codecs.decode(hex_str, 'hex').decode('utf-8', errors='ignore')
        except:
            return match.group(0)

    code = re.sub(r'\\x([0-9a-fA-F]{2})|%x([0-9a-fA-F]{2})', replace_hex, code)
    return re.sub(r'\\(\d{1,3})', lambda m: chr(int(m.group(1))), code)

def _decode_base64_strings(code: str) -> str:
    """Decodes common base64-encoded string patterns (e.g., in loadstring)"""
    def replace_base64(match):
        b64_str = match.group(1)
        try:
            decoded_bytes = base64.b64decode(b64_str)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            if re.match(r'^\s*(local|function|if|while|for|repeat)', decoded_str.strip()):
                return f"--- DECODED_BASE64_START ---\n{decoded_str}\n--- DECODED_BASE64_END ---"
            return f'"{_unescape_lua_string(decoded_str)}"'
        except:
            return match.group(0)

    return re.sub(r'(?:loadstring|rawset|setfenv)\s*\(\s*["\"]([a-zA-Z0-9+/=]+)["\"]\s*\)', replace_base64, code)

def _decode_unicode_escapes(code: str) -> str:
    """Decodes \uXXXX, \UXXXXXXXX, and other common escape sequences."""
    return re.sub(r'\\(?:u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8})', lambda m: _unescape_lua_string(m.group(0)), code)

def _resolve_string_concatenation(code: str) -> str:
    """Resolves simple 'a' .. 'b' patterns into 'ab'."""
    code = re.sub(r'(".*?")\s*\.\.\s*(".*?")', lambda m: f'"{m.group(1)}{m.group(2)}"', code)
    code = re.sub(r"('(.*?)')\s*\.\.\s*('(.*?)')", lambda m: f"'{m.group(2)}{m.group(4)}'", code)
    return code

def _remove_simple_dead_code(code: str) -> str:
    """Removes very simple patterns of dead code or obfuscation junk."""
    patterns = [
        r'local _[a-zA-Z0-9]{5,}\s*=\s*[0-9]+\s*;\n',
        r'local _\w+\s*=\s*nil\s*;\n',
        r'do\s+-- junk\s+.*?end\s+-- junk\n',
        r'if\s+(false|nil)\s+then.*?end\n',
        r'while\s+(false|nil)\s+do.*?end\n',
    ]
    for pattern in patterns:
        code = re.sub(pattern, '', code, flags=re.DOTALL | re.IGNORECASE)
    return code

def _remove_wrapper_functions(code: str) -> str:
    """
    Attempts to remove the common top-level wrapper functions used by obfuscators,
    especially those returning a large obfuscated function.
    """
    code = re.sub(r'^\s*--\[\[This file was protected with MoonSec V3\]\]:gsub\(\".+\", \(function\(a\) __xirluziHIZB = a; end\)\);\s*', '', code, flags=re.MULTILINE)

    match = re.search(r'return\s*\(function\s*\(t,.*?\)\s*(.*)\s*end\)\)\s*$', code, flags=re.DOTALL)
    if match:
        return match.group(1).strip()

    return code

def _simplify_getfenv_setfenv(code: str) -> str:
    """
    Attempts to simplify common getfenv/setfenv patterns.
    """
    code = re.sub(r'setfenv\s*\(\s*(0|1|2),\s*_ENV\s*\)', '', code)
    code = re.sub(r'getfenv\s*\(\s*\d+\s*\)', '_ENV', code)
    return code

def deobf_moonsec_v3(code: str) -> str:
    """
    Applies heuristics for Moonsec v3 deobfuscation.
    This includes wrapper removal, enhanced string decoding, and some environment cleanup.
    Full deobfuscation is extremely complex and often involves bytecode analysis or VM emulation.
    """
    output_messages = []

    original_len = len(code)
    code = _remove_wrapper_functions(code)
    if len(code) < original_len:
        output_messages.append("- Removed top-level obfuscator wrapper.")

    code = _unescape_lua_string(code)
    code = _decode_hex_strings(code)
    code = _decode_unicode_escapes(code)
    code = _decode_base64_strings(code)
    code = _resolve_string_concatenation(code)

    code = _simplify_getfenv_setfenv(code)

    cleaned_code = beautify_lua(code)
    output_messages.append("- Applied enhanced string/escape decoding and environment cleanup.")
    output_messages.append("- Applied basic formatting.")

    return f"--- Moonsec v3 Deobfuscation (Heuristic Clean-up) ---\n"
           f"\n".join(output_messages) +
           f"\n\n{cleaned_code}"

def deobf_jayfuscator(code: str) -> str:
    """
    Placeholder for Jayfuscator deobfuscation logic.
    Jayfuscator uses techniques like string encryption, control flow flattening, and VM.
    This function currently applies basic formatting and common cleanup patterns.
    """
    cleaned_code = beautify_lua(code)
    cleaned_code = _unescape_lua_string(cleaned_code)
    cleaned_code = _decode_hex_strings(cleaned_code)
    cleaned_code = _decode_unicode_escapes(cleaned_code)
    cleaned_code = _resolve_string_concatenation(cleaned_code)
    return f"--- Jayfuscator Deobfuscation (Basic Clean-up) ---\n\n{cleaned_code}"

def deobf_luraph(code: str) -> str:
    """
    Placeholder for Luraph deobfuscation logic.
    Luraph is a very strong commercial obfuscator, often involving custom VMs.
    This function currently applies basic formatting and common cleanup patterns.
    """
    cleaned_code = beautify_lua(code)
    cleaned_code = _unescape_lua_string(cleaned_code)
    cleaned_code = _decode_hex_strings(cleaned_code)
    cleaned_code = _decode_unicode_escapes(cleaned_code)
    cleaned_code = _resolve_string_concatenation(cleaned_code)
    return f"--- Luraph Deobfuscation (Basic Clean-up) ---\n\n{cleaned_code}"

def deobf_custom(code: str, keywords: list = None, techniques: list = None) -> str:
    """
    Applies custom deobfuscation logic based on selected techniques and searches for keywords.
    Supported techniques (via 'techniques' list):
    - 'wrapper_remove': Attempts to remove top-level obfuscator wrapper functions.
    - 'hex_decode': Decodes common hex-encoded strings (e.g., \xXX, %xXX).
    - 'base64_decode': Decodes base64-encoded strings, especially within loadstring.
    - 'unicode_decode': Decodes common unicode/escape sequences (e.g., \uXXXX, \DDD).
    - 'basic_string_concat': Resolves simple 'a' .. 'b' patterns into 'ab'.
    - 'xor_decode': Attempts a very basic XOR decoding (requires pattern matching).
    - 'dead_code_remove': Removes very simple patterns of dead/junk code.
    - 'simplify_fenv': Simplifies patterns involving getfenv/setfenv.

    More advanced techniques (VM, function tables, control flow flattening, etc.) would require
    dedicated Lua parsers, AST manipulation, or even VM emulation, and are beyond the scope
    of simple regex-based replacements.
    """
    output = [f"--- Custom Deobfuscation ---"]
    output.append(f"Selected techniques: {', '.join(techniques) if techniques else 'None specified'}")
    output.append(f"Keywords to search for: {', '.join(keywords) if keywords else 'None specified'}")

    cleaned_code = code

    if techniques:
        if "wrapper_remove" in techniques:
            original_len = len(cleaned_code)
            cleaned_code = _remove_wrapper_functions(cleaned_code)
            if len(cleaned_code) < original_len:
                output.append("- Applied top-level wrapper removal.")

        if "unicode_decode" in techniques:
            cleaned_code = _unescape_lua_string(cleaned_code)
            cleaned_code = _decode_unicode_escapes(cleaned_code)
            output.append("- Applied unicode/escape sequence decoding.")

        if "hex_decode" in techniques:
            cleaned_code = _decode_hex_strings(cleaned_code)
            output.append("- Applied hex decoding (`\\xXX`, `%xXX`, `\\DDD` patterns).")

        if "base64_decode" in techniques:
            cleaned_code = _decode_base64_strings(cleaned_code)
            output.append("- Applied basic Base64 decoding (in `loadstring` or quoted).")

        if "basic_string_concat" in techniques:
            cleaned_code = _resolve_string_concatenation(cleaned_code)
            output.append("- Applied basic string concatenation resolution (`\"a\" .. \"b\"`).")

        if "xor_decode" in techniques:
            def decode_xor_string(match):
                hex_encoded_bytes = match.group(0)
                try:
                    byte_string = hex_encoded_bytes.encode('latin1').decode('unicode_escape').encode('latin1')
                    key = 0xAC
                    decoded_bytes = bytes([b ^ key for b in byte_string])
                    return decoded_bytes.decode('utf-8', errors='ignore')
                except Exception:
                    return match.group(0)

            cleaned_code = re.sub(r'(\[xX][0-9a-fA-F]{2})+', decode_xor_string, cleaned_code)
            output.append("- Applied basic XOR decoding (attempted with a guessed key, highly specific to patterns).")

        if "dead_code_remove" in techniques:
            cleaned_code = _remove_simple_dead_code(cleaned_code)
            output.append("- Applied simple dead code removal heuristics.")

        if "simplify_fenv" in techniques:
            cleaned_code = _simplify_getfenv_setfenv(cleaned_code)
            output.append("- Applied getfenv/setfenv simplification heuristics.")


    output.append("\n--- Cleaned Code (formatted) ---")
    cleaned_code = beautify_lua(cleaned_code)
    output.append(cleaned_code)

    if keywords:
        found_keywords = []
        for keyword in keywords:
            if re.search(re.escape(keyword), cleaned_code, re.IGNORECASE):
                found_keywords.append(keyword)

        if found_keywords:
            output.append("\n--- Keywords Found in Cleaned Code ---")
            output.append(f"Found: {', '.join(found_keywords)}")
        else:
            output.append("\n--- Keywords Search ---")
            output.append("No specified keywords found in the cleaned code.")

    return "\n".join(output)
