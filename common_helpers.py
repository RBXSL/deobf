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

    string_constants = re.findall(r'local \w+\s*=\s*(".*?"|\'.*?\')', code)
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

def _unescape_lua_string_safe(text: str) -> str:
    """
    Safely decodes Lua-style escape sequences in a string.
    Handles \\xXX, \\uXXXX, \\u{XXXX}, \\DDD (octal), and standard escapes.
    Invalid or incomplete sequences are left as is to prevent SyntaxError.
    """
    def replace_match(match):
        full_match = match.group(0)
        
        # Hex escape \xXX
        if match.group(1):
            try:
                return chr(int(match.group(1), 16))
            except ValueError:
                return full_match
        
        # Unicode escape \uXXXX
        elif match.group(2):
            try:
                return chr(int(match.group(2), 16))
            except ValueError:
                return full_match
        
        # Unicode escape \u{XXXX}
        elif match.group(3):
            try:
                return chr(int(match.group(3), 16))
            except ValueError:
                return full_match
        
        # Octal escape \DDD
        elif match.group(4):
            try:
                return chr(int(match.group(4), 8))
            except ValueError:
                return full_match
        
        # Standard escapes \a \b \f \n \r \t \v \\ \" \'
        elif match.group(5):
            char_code = match.group(5)
            if char_code == 'a': return '\a'
            if char_code == 'b': return '\b'
            if char_code == 'f': return '\f'
            if char_code == 'n': return '\n'
            if char_code == 'r': return '\r'
            if char_code == 't': return '\t'
            if char_code == 'v': return '\v'
            if char_code == '\\': return '\\'
            if char_code == '"': return '"'
            if char_code == "'": return "'"
            return full_match # Should not happen if regex is correct
        
        return full_match # Fallback, should capture only specific patterns

    # Regex to capture various Lua escape sequences robustly
    pattern = re.compile(
        r'\\x([0-9a-fA-F]{2})'        # Hex escapes \xXX
        r'|\\u([0-9a-fA-F]{4})'       # Unicode escapes \uXXXX
        r'|\\u\{([0-9a-fA-F]+)\}'     # Unicode escapes \u{XXXX}
        r'|\\([0-9]{1,3})'            # Octal escapes \DDD (up to 3 digits)
        r'|\\([abfnrtv\\\'"])'        # Standard single-char escapes
    )
    
    return pattern.sub(replace_match, text)


def _decode_hex_strings(code: str) -> str:
    """Decodes common hex-encoded string patterns (e.g., \\xXX, %xXX)"""
    # This now primarily handles %xXX patterns, as \\xXX is covered by _unescape_lua_string_safe
    def replace_hex_percent(match):
        hex_str = match.group(1)
        try:
            return codecs.decode(hex_str, 'hex').decode('utf-8', errors='ignore')
        except: 
            return match.group(0) # Return original if decoding fails
    
    code = re.sub(r'%x([0-9a-fA-F]{2})', replace_hex_percent, code)
    return code

def _decode_base64_strings(code: str) -> str:
    """Decodes common base64-encoded string patterns (e.g., in loadstring)"""
    def replace_base64(match):
        b64_str = match.group(1)
        try:
            decoded_bytes = base64.b64decode(b64_str)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            # Apply safe unescaping to the decoded string, as it might contain escapes
            unescaped_decoded_str = _unescape_lua_string_safe(decoded_str)

            if re.match(r'^\s*(local|function|if|while|for|repeat)', unescaped_decoded_str.strip()):
                return f"--- DECODED_BASE64_START ---\n{unescaped_decoded_str}\n--- DECODED_BASE64_END ---"
            return f'"{unescaped_decoded_str}"'
        except:
            return match.group(0)
    
    return re.sub(r'(?:loadstring|rawset|setfenv)\s*\(\s*["\"]([a-zA-Z0-9+/=]+)["\"]\s*\)', replace_base64, code)


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
    # Regex for Moonsec V3 initial wrapper
    code = re.sub(r'^\s*--\[\[This file was protected with MoonSec V3\]\]:gsub\(\".+\", \(function\(a\) __xirluziHIZB = a; end\)\);\s*', '', code, flags=re.MULTILINE)
    
    # Pattern for the main return(function(...) ... end) wrapper
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

def _decode_xor_string_basic(code: str) -> str:
    """
    Basic XOR decoding heuristic. This is very limited and assumes specific patterns.
    """
    def decode_xor(match):
        encoded_str = match.group(1)
        # Attempt to decode as hex bytes
        try:
            bytes_str = encoded_str.encode('latin1').decode('unicode_escape').encode('latin1')
            key = 0xAC # Example simple key, often needs to be found via analysis
            decoded = bytes([b ^ key for b in bytes_str]).decode('utf-8', errors='ignore')
            return f'"{_unescape_lua_string_safe(decoded)}"'
        except Exception:
            return match.group(0)
    
    # Target patterns that look like hex-encoded strings being passed to an XOR function or being
    # defined directly with hex escapes.
    code = re.sub(r'["\']((\\x[0-9a-fA-F]{2})+)+["\']', decode_xor, code)
    return cod
