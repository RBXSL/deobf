import re
import codecs

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

def deobf_moonsec_v3(code: str) -> str:
    """
    Placeholder for Moonsec v3 deobfuscation logic.
    Real Moonsec v3 deobfuscation is complex and often involves bytecode analysis or specific VM understanding.
    This function currently applies basic formatting and common cleanup patterns.
    """
    cleaned_code = beautify_lua(code)

    # Example: Simple hex string decoding pattern (common in some obfuscators)
    def decode_hex_string(match):
        hex_str = match.group(1).replace('\\x', '')
        try:
            return codecs.decode(hex_str, 'hex').decode('utf-8')
        except:
            return match.group(0) # Return original if decoding fails

    cleaned_code = re.sub(r'\\x([0-9a-fA-F]{2})', decode_hex_string, cleaned_code)

    return f"--- Moonsec v3 Deobfuscation (Basic Clean-up) ---\n\n{cleaned_code}"

def deobf_jayfuscator(code: str) -> str:
    """
    Placeholder for Jayfuscator deobfuscation logic.
    Jayfuscator uses techniques like string encryption, control flow flattening, and VM.
    A full deobfuscator would require significant reverse engineering.
    This function currently applies basic formatting.
    """
    cleaned_code = beautify_lua(code)
    # Add specific Jayfuscator common patterns here if identified
    return f"--- Jayfuscator Deobfuscation (Basic Clean-up) ---\n\n{cleaned_code}"

def deobf_luraph(code: str) -> str:
    """
    Placeholder for Luraph deobfuscation logic.
    Luraph is a very strong commercial obfuscator, often involving custom VMs.
    Full deobfuscation is extremely difficult without specialized tools or exploits.
    This function currently applies basic formatting.
    """
    cleaned_code = beautify_lua(code)
    # Add specific Luraph common patterns here if identified
    return f"--- Luraph Deobfuscation (Basic Clean-up) ---\n\n{cleaned_code}"

def deobf_custom(code: str, keywords: list = None, techniques: list = None) -> str:
    """
    Applies custom deobfuscation logic based on selected techniques and searches for keywords.
    Currently supports: 'hex_decode', 'basic_string_concat', and 'xor_decode' (placeholder).
    More advanced techniques (VM, function tables) would require dedicated parsers/engines.
    """
    output = [f"--- Custom Deobfuscation ---"]
    output.append(f"Selected techniques: {', '.join(techniques) if techniques else 'None specified'}")
    output.append(f"Keywords to search for: {', '.join(keywords) if keywords else 'None specified'}")

    cleaned_code = code

    if techniques:
        # Apply selected techniques
        if "hex_decode" in techniques:
            def decode_hex_string(match):
                hex_str = match.group(1).replace('\\x', '')
                try:
                    return codecs.decode(hex_str, 'hex').decode('utf-8')
                except:
                    return match.group(0)
            cleaned_code = re.sub(r'\\x([0-9a-fA-F]{2})', decode_hex_string, cleaned_code)
            output.append("- Applied basic hex decoding.")

        if "basic_string_concat" in techniques:
            # Example: "a" .. "b" -> "ab"
            # This is a simple regex and won't handle all cases (e.g., variables)
            cleaned_code = re.sub(r'"(.*?)"\s*\.\.\s*"(.*?)"', r'"\1\2"', cleaned_code)
            output.append("- Applied basic string concatenation resolution.")

        if "xor_decode" in techniques:
            # Placeholder for XOR decoding. This is highly dependent on the specific XOR pattern (key, loop, etc.)
            # A real implementation would need to parse the XOR logic.
            output.append("- Attempted XOR decoding (placeholder: needs specific XOR logic).")

        # Add more custom technique placeholders here

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
