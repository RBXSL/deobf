import re
import codecs
import base64

def beautify_lua(code: str) -> str:
    """
    Applies basic formatting and indentation to Lua code.
    This is a preliminary step for all deobfuscation efforts.
    """
    # Simple re-indentation (can be improved with a proper Lua formatter)
    indent_level = 0
    formatted_lines = []
    lines = code.split('\n')
    for line in lines:
        stripped_line = line.strip()
        if not stripped_line:
            formatted_lines.append("")
            continue

        # Adjust indent for 'end'
        if stripped_line.startswith("end") or stripped_line.startswith("until") or stripped_line.startswith("else") or stripped_line.startswith("elseif"):
            indent_level = max(0, indent_level - 1)

        formatted_lines.append("    " * indent_level + stripped_line)

        # Adjust indent for keywords that introduce a block
        if stripped_line.endswith("do") or stripped_line.endswith("then") or stripped_line.startswith("function") or stripped_line.startswith("repeat"):
            indent_level += 1
        elif stripped_line.startswith("else"):
            indent_level += 1 # 'else' block starts

    return "\n".join(formatted_lines)

def deobf_constant_dump(code: str) -> str:
    """
    Extracts and lists potential constants and function definitions from the Lua code.
    This is not full deobfuscation, but a way to inspect hidden values.
    """
    output = ["--- Constant and Function Dump ---"]

    # Try to find string constants
    string_constants = re.findall(r'local \w+\s*=\s*(".*?"|".*?")', code)
    if string_constants:
        output.append("\n**String Constants Found:**")
        for const in set(string_constants): # Use set to avoid duplicates
            output.append(f"- {const}")

    # Try to find numeric constants
    numeric_constants = re.findall(r'local \w+\s*=\s*(\d+(\.\d*)?)', code)
    if numeric_constants:
        output.append("\n**Numeric Constants Found:**")
        for const, _ in set(numeric_constants):
            output.append(f"- {const}")

    # Try to find function definitions
    function_defs = re.findall(r'(local\s+)?function\s+(\w+)\s*\(.*?\)', code)
    if function_defs:
        output.append("\n**Function Definitions Found:**")
        for local_keyword, func_name in set(function_defs):
            output.append(f"- {local_keyword or ''}function {func_name}")

    if len(output) == 1: # Only header was added
        output.append("\nNo obvious constants or functions found with basic parsing.")

    output.append("\n--- Original Code (formatted) ---")
    output.append(beautify_lua(code))

    return "\n".join(output)

# --- Helper Functions for Deobfuscation Techniques ---

def _decode_hex_strings(code: str) -> str:
    """Decodes common hex-encoded string patterns (e.g., \xXX, %xXX)"""
    def replace_hex(match):
        hex_str = match.group(1) or match.group(2)
        try:
            return codecs.decode(hex_str, 'hex').decode('utf-8', errors='ignore')
        except:
            return match.group(0) # Return original if decoding fails

    # Matches \xHH or %xHH patterns
    return re.sub(r'\\x([0-9a-fA-F]{2})|%x([0-9a-fA-F]{2})', replace_hex, code)

def _decode_base64_strings(code: str) -> str:
    """Decodes common base64-encoded string patterns (e.g., in loadstring)"""
    def replace_base64(match):
        b64_str = match.group(1)
        try:
            # Base64 strings are often embedded within Lua, so we need to handle quotes
            decoded_bytes = base64.b64decode(b64_str)
            # Try to decode as UTF-8, but fall back to a more lenient encoding if needed
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            # If it looks like Lua code, return it directly, otherwise keep it quoted
            if re.match(r'^\s*(local|function|if|while|for|repeat)', decoded_str.strip()):
                return f"--- DECODED_BASE64_START ---\n{decoded_str}\n--- DECODED_BASE64_END ---"
            return f'"{decoded_str}"'
        except:
            return match.group(0)

    # Matches patterns like 'loadstring("...")' or just quoted base64 strings
    return re.sub(r'(?:loadstring|rawset|setfenv)\s*\(\s*["\']([a-zA-Z0-9+/=]+)["\']\s*\)', replace_base64, code)

def _decode_unicode_escapes(code: str) -> str:
    """Decodes \uXXXX, \UXXXXXXXX, \xXX, and other common Python/Lua escape sequences."""
    def replace_escape(match):
        escaped_char = match.group(0)
        try:
            # Python's string literal parsing handles most of these
            return escaped_char.encode('latin1').decode('unicode_escape')
        except:
            return escaped_char

    # Matches various escape sequences
    return re.sub(r'\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|.)', replace_escape, code)

def _resolve_string_concatenation(code: str) -> str:
    """Resolves simple 'a' .. 'b' patterns into 'ab'."""
    # This regex is an example and might need refinement for complex cases
    return re.sub(r'"(.*?)"\s*\.\.\s*"(.*?)"', r'"\1\2"', code)

def _remove_simple_dead_code(code: str) -> str:
    """
    Removes very simple patterns of dead code or obfuscation junk.
    This is highly heuristic and may remove valid code if patterns are too broad.
    """
    # Example: remove assignments to unused locals that match a junk pattern
    # Warning: This is very basic and prone to errors.
    patterns = [
        r'local _[a-zA-Z0-9]{5,}\s*=\s*[0-9]+\s*;\n', # local _xxxx = 123;
        r'local _\w+\s*=\s*nil\s*;\n',               # local _x = nil;
        r'do\s+-- junk\s+.*?end\s+-- junk\n',        # simple do..end junk blocks
    ]
    for pattern in patterns:
        code = re.sub(pattern, '', code, flags=re.DOTALL)
    return code


def deobf_moonsec_v3(code: str) -> str:
    """
    Placeholder for Moonsec v3 deobfuscation logic.
    Real Moonsec v3 deobfuscation is complex and often involves bytecode analysis or specific VM understanding.
    This function currently applies basic formatting, hex decoding, and unicode escape decoding.
    """
    cleaned_code = beautify_lua(code)
    cleaned_code = _decode_hex_strings(cleaned_code)
    cleaned_code = _decode_unicode_escapes(cleaned_code)
    # Add more specific Moonsec v3 patterns here if identified
    return f"--- Moonsec v3 Deobfuscation (Basic Clean-up) ---\n\n{cleaned_code}"

def deobf_jayfuscator(code: str) -> str:
    """
    Placeholder for Jayfuscator deobfuscation logic.
    Jayfuscator uses techniques like string encryption, control flow flattening, and VM.
    A full deobfuscator would require significant reverse engineering.
    This function currently applies basic formatting, hex decoding, and unicode escape decoding.
    """
    cleaned_code = beautify_lua(code)
    cleaned_code = _decode_hex_strings(cleaned_code)
    cleaned_code = _decode_unicode_escapes(cleaned_code)
    # Add more specific Jayfuscator common patterns here if identified
    return f"--- Jayfuscator Deobfuscation (Basic Clean-up) ---
\n{cleaned_code}"

def deobf_luraph(code: str) -> str:
    """
    Placeholder for Luraph deobfuscation logic.
    Luraph is a very strong commercial obfuscator, often involving custom VMs.
    Full deobfuscation is extremely difficult without specialized tools or exploits.
    This function currently applies basic formatting, hex decoding, and unicode escape decoding.
    """
    cleaned_code = beautify_lua(code)
    cleaned_code = _decode_hex_strings(cleaned_code)
    cleaned_code = _decode_unicode_escapes(cleaned_code)
    # Add more specific Luraph common patterns here if identified
    return f"--- Luraph Deobfuscation (Basic Clean-up) ---
\n{cleaned_code}"

def deobf_custom(code: str, keywords: list = None, techniques: list = None) -> str:
    """
    Applies custom deobfuscation logic based on selected techniques and searches for keywords.
    Supported techniques (via 'techniques' list):
    - 'hex_decode': Decodes common hex-encoded strings (e.g., \xXX, %xXX).
    - 'base64_decode': Decodes base64-encoded strings, especially within loadstring.
    - 'unicode_decode': Decodes common unicode/escape sequences (e.g., \uXXXX).
    - 'basic_string_concat': Resolves simple 'a' .. 'b' patterns into 'ab'.
    - 'xor_decode': Attempts a very basic XOR decoding (requires pattern matching).
    - 'dead_code_remove': Removes very simple patterns of dead/junk code.

    More advanced techniques (VM, function tables, control flow flattening, etc.) would require
    dedicated Lua parsers, AST manipulation, or even VM emulation, and are beyond the scope
    of simple regex-based replacements.
    """
    output = [f"--- Custom Deobfuscation ---"]
    output.append(f"Selected techniques: {', '.join(techniques) if techniques else 'None specified'}")
    output.append(f"Keywords to search for: {', '.join(keywords) if keywords else 'None specified'}")

    cleaned_code = code

    if techniques:
        # Apply selected techniques
        if "hex_decode" in techniques:
            cleaned_code = _decode_hex_strings(cleaned_code)
            output.append("- Applied hex decoding (`\\xXX`, `%xXX` patterns).")

        if "base64_decode" in techniques:
            cleaned_code = _decode_base64_strings(cleaned_code)
            output.append("- Applied basic Base64 decoding (in `loadstring` or quoted).")

        if "unicode_decode" in techniques:
            cleaned_code = _decode_unicode_escapes(cleaned_code)
            output.append("- Applied unicode/escape sequence decoding.")

        if "basic_string_concat" in techniques:
            cleaned_code = _resolve_string_concatenation(cleaned_code)
            output.append("- Applied basic string concatenation resolution (`\"a\" .. \"b\"`).")

        if "xor_decode" in techniques:
            # This is a very basic XOR decoding example.
            # Real XOR deobfuscation is highly specific to the obfuscator's implementation (key, pattern).
            # This attempts to find patterns like '\xHH\xHH' and XOR them with a guessed key (e.g., 0xAC)
            # A more robust solution would require analyzing the XOR logic in the obfuscated code.

            def decode_xor_string(match):
                hex_encoded_bytes = match.group(0) # e.g., '\xAB\xCD'
                try:
                    byte_string = hex_encoded_bytes.encode('latin1').decode('unicode_escape').encode('latin1')
                    key = 0xAC # Example: Try XORing with a common single-byte key
                    decoded_bytes = bytes([b ^ key for b in byte_string])
                    return decoded_bytes.decode('utf-8', errors='ignore')
                except Exception:
                    return match.group(0) # Return original if decoding fails

            cleaned_code = re.sub(r'(\\[xX][0-9a-fA-F]{2})+', decode_xor_string, cleaned_code)
            output.append("- Applied basic XOR decoding (attempted with a guessed key, highly specific to patterns).")

        if "dead_code_remove" in techniques:
            cleaned_code = _remove_simple_dead_code(cleaned_code)
            output.append("- Applied simple dead code removal heuristics.")

    output.append("\n--- Cleaned Code (formatted) ---")
    # Apply beautify_lua after all cleaning attempts
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
