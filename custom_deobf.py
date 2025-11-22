from .common_helpers import (
    beautify_lua,
    deobf_constant_dump,
    _unescape_lua_string_safe,
    _decode_hex_strings,
    _decode_base64_strings,
    _resolve_string_concatenation,
    _simplify_getfenv_setfenv,
    _decode_xor_string_basic,
    _remove_simple_dead_code,
    _remove_wrapper_functions # Common wrapper removal
)

# Custom Deobf specific functions or techniques can be added here
# For now, it largely orchestrates the common helpers and specific obfuscator techniques

def deobf_custom(code: str, keywords: list = None, techniques: list = None) -> str:
    """
    Applies custom deobfuscation logic based on selected techniques and searches for keywords.
    Supported techniques (via 'techniques' list):
    - 'beautify': Applies basic Lua formatting and indentation.
    - 'constant_dump': Extracts and lists constants and function definitions.
    - 'wrapper_remove': Attempts to remove top-level obfuscator wrapper functions (e.g., Moonsec).
    - 'hex_decode': Decodes common hex-encoded strings (e.g., \\xXX, %xXX).
    - 'base64_decode': Decodes base64-encoded strings, especially within loadstring.
    - 'unicode_decode': Decodes common unicode/escape sequences (e.g., \\uXXXX, \\DDD).
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
    applied_techniques = []

    if techniques:
        # Prioritize formatting and dumping first if requested, as it helps readability
        if "beautify" in techniques:
            cleaned_code = beautify_lua(cleaned_code)
            applied_techniques.append("- Applied basic formatting (beautify).")
        
        if "constant_dump" in techniques:
            # Constant dump is usually a reporting function, not a modification function,
            # so we run it on the current cleaned_code and add its output to messages.
            dump_output = deobf_constant_dump(cleaned_code)
            output.append("\n" + dump_output + "\n")
            applied_techniques.append("- Performed constant and function dump.")

        if "wrapper_remove" in techniques:
            original_len = len(cleaned_code)
            cleaned_code = _remove_wrapper_functions(cleaned_code)
            if len(cleaned_code) < original_len:
                applied_techniques.append("- Applied top-level wrapper removal.")

        # String/encoding related decodings
        if "unicode_decode" in techniques:
            cleaned_code = _unescape_lua_string_safe(cleaned_code)
            applied_techniques.append("- Applied unicode/escape sequence decoding.")

        if "hex_decode" in techniques:
            cleaned_code = _decode_hex_strings(cleaned_code)
            applied_techniques.append("- Applied hex decoding (\\xXX, %xXX, \\DDD patterns).")

        if "base64_decode" in techniques:
            cleaned_code = _decode_base64_strings(cleaned_code)
            applied_techniques.append("- Applied basic Base64 decoding (in `loadstring` or quoted).")
            
        if "basic_string_concat" in techniques:
            cleaned_code = _resolve_string_concatenation(cleaned_code)
            applied_techniques.append("- Applied basic string concatenation resolution (`\"a\" .. \"b\"`).")
            
        if "xor_decode" in techniques:
            # Assuming _decode_xor_string_basic is implemented in common_helpers
            cleaned_code = _decode_xor_string_basic(cleaned_code)
            applied_techniques.append("- Applied basic XOR decoding (attempted with a guessed key, highly specific to patterns).")

        # Code structure/simplification
        if "dead_code_remove" in techniques:
            cleaned_code = _remove_simple_dead_code(cleaned_code)
            applied_techniques.append("- Applied simple dead code removal heuristics.")

        if "simplify_fenv" in techniques:
            cleaned_code = _simplify_getfenv_setfenv(cleaned_code)
            applied_techniques.append("- Applied getfenv/setfenv simplification heuristics.")

        # Add other general techniques here based on the master list
        # E.g., Basic renaming/demangling heuristics could go here if generic enough
        # Note: Advanced control flow, VM, AST manipulation are beyond simple regex.

    if applied_techniques:
        output.append("\nApplied Transformations:")
        output.extend(applied_techniques)

    output.append("\n--- Cleaned Code (formatted) ---")
    # Apply beautify_lua at the very end if not already applied
    if "beautify" not in techniques:
        cleaned_code = beautify_lua(cleaned_code)
        output.append("- Applied final Lua code formatting (beautification).")
    
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
