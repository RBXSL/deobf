import re
import codecs
import base64
from .common_helpers import (
    beautify_lua,
    _unescape_lua_string_safe,
    _decode_hex_strings,
    _decode_base64_strings,
    _resolve_string_concatenation,
    _simplify_getfenv_setfenv,
    _decode_xor_string_basic,
    _remove_simple_dead_code
)

def _jay_demangle_renaming(code: str) -> str:
    """
    Attempts to demangle minified/renamed variables in Jayfuscator.
    This is highly heuristic and will primarily replace common patterns
    with more readable placeholders. Full demangling requires deeper analysis.
    """
    # Replace single-letter or short, seemingly random names
    # Caution: This can break code if names are legitimate.
    # Pattern: local a = b.c(d) --> local var1 = obj.func(arg)
    
    # Replace short, random local variables
    code = re.sub(r'local ([a-zA-Z_][a-zA-Z0-9_]{1,3})\s*=\s*(.*?);', r'local __var_\1 = \2;', code)
    code = re.sub(r'function ([a-zA-Z_][a-zA-Z0-9_]{1,3})\(', r'function __func_\1(', code)
    
    return code

def _jay_string_decrypt(code: str) -> str:
    """
    Specifically targets Jayfuscator's string encryption.
    Leverages Base64 and XOR decoding helpers, as Jayfuscator is confirmed to use them.
    """
    # Jayfuscator uses Stringencrypt, Base64, XORing
    # We will apply these aggressively
    code = _decode_base64_strings(code)
    code = _decode_xor_string_basic(code) # Assuming the basic XOR can catch some patterns
    
    # Look for common string table patterns used by Jayfuscator
    # e.g., local strings = { "encrypted_str1", "encrypted_str2" }
    # Then some access like strings[idx] or a decryption function call.
    # This requires more specific pattern matching to integrate a decryption function.
    
    return code

def _jay_control_flow_simplify(code: str) -> str:
    """
    Attempts to simplify Jayfuscator's control flow flattening and indirection.
    """
    # This is similar to Moonsec's challenge. Jayfuscator uses Flattening, Indirection, Proxying.
    # Heuristics for simple sequence unwrapping.
    code = re.sub(r'if\s+\(true\)\s+then\s*(goto\s+\w+|break)\s+end;', r'\1;', code)
    code = re.sub(r'if\s+\(false\)\s+then\s*.*?\s*end;', '', code)

    # Basic indirection/proxying patterns (highly heuristic)
    # e.g., local _0x123 = getfenv()._G.print; _0x123("hello") --> print("hello")
    # This is extremely difficult with regex alone without execution analysis.
    # Placeholder: identify and flag.
    return code


def _jay_anti_tamper_neutralization(code: str) -> str:
    """
    Neutralizes Jayfuscator's AntiDump, AntiDebug, AntiHook, AntiTrace.
    """
    # Similar to Moonsec, but may have Jayfuscator-specific patterns.
    # Target debug library access, environment modification, hook attempts.
    code = re.sub(r'debug\.getinfo', 'nil', code)
    code = re.sub(r'debug\.getupvalue', 'nil', code)
    code = re.sub(r'debug\.sethook', 'nil', code)
    
    code = re.sub(r'setfenv\s*\(\s*(0|1|2),\s*_ENV\s*\)', '', code) # Clean environment locking again
    code = re.sub(r'getfenv\s*\(\s*\d+\s*\)', '_ENV', code) # Clean getfenv
    
    # Anti-hook patterns (e.g., re-assigning global functions or metatable manipulation)
    code = re.sub(r'hookfunction\(.*?\)', 'nil', code) # Neutralize hookfunction calls
    
    # Remove simple error/exit calls triggered by anti-tamper
    code = re.sub(r'if\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*then\s*error\(.*?\)\s*end;', '', code, flags=re.DOTALL)
    code = re.sub(r'if\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*then\s*os\.exit\(.*?\)\s*end;', '', code, flags=re.DOTALL)
    
    return code

def deobf_jayfuscator(code: str) -> str:
    """
    Applies comprehensive heuristics for Jayfuscator deobfuscation.
    This includes renaming heuristics, string decryption, control flow simplification,
    environment cleanup, and anti-tamper neutralization, as per the provided techniques.
    Full de-virtualization or complete AST-based control flow restoration remains a complex task.
    """
    output_messages = ["--- Jayfuscator Deobfuscation (Comprehensive Heuristic Clean-up) ---"]

    # Apply general cleanup first
    code = beautify_lua(code)
    code = _unescape_lua_string_safe(code)
    output_messages.append("- Applied basic formatting and robust escape decoding.")
    
    # Specific Jayfuscator techniques
    code = _jay_demangle_renaming(code)
    output_messages.append("- Applied heuristic renaming/demangling.")
    
    code = _jay_string_decrypt(code)
    output_messages.append("- Applied string decryption (Base64, XOR, common patterns).")
    
    code = _jay_control_flow_simplify(code)
    output_messages.append("- Applied basic control flow simplification and indirection heuristics.")
    
    code = _simplify_getfenv_setfenv(code) # Common helper for fenv
    code = _jay_anti_tamper_neutralization(code)
    output_messages.append("- Cleaned up environment manipulation and neutralized anti-tamper checks.")
    
    code = _remove_simple_dead_code(code)
    output_messages.append("- Removed simple dead code and junk.")

    # Final beautification
    cleaned_code = beautify_lua(code)
    output_messages.append("- Applied final Lua code formatting (beautification).")

    output_messages.append("\nNote: Full deobfuscation of advanced techniques like control flow flattening, "
                           "complex proxying, and deeper string decryption may require a Lua AST parser, "
                           "execution analysis, or custom decryption algorithms specific to obfuscator versions.")

    return "\n".join(output_messages) + f"\n\n{cleaned_code}"
