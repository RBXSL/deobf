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

def _moonsec_remove_initial_wrapper(code: str) -> str:
    """
    Removes the initial 'MoonSec V3' gsub wrapper.
    Example: [[This file was protected with MoonSec V3]]:gsub('.+', (function(a) __xirluziHIZB = a; end));
    """
    return re.sub(
        r'^\s*--\[\[This file was protected with MoonSec V3\]\]:gsub\(\'.+\', \(function\(a\) __xirluziHIZB = a; end\)\);\s*', 
        '', 
        code, 
        flags=re.MULTILINE
    )

def _moonsec_extract_main_function(code: str) -> str:
    """
    Extracts the main obfuscated function body from the top-level 'return(function(...) ... end)' wrapper.
    """
    match = re.search(
        r'return\s*\(function\s*\(t,.*?\)\s*(.*)\s*end\)\)\s*$', 
        code, 
        flags=re.DOTALL
    )
    if match:
        return match.group(1).strip()
    return code

def _moonsec_simplify_control_flow(code: str) -> str:
    """
    Attempts to simplify very basic control-flow flattening patterns
    like 'while true do if x == 1 then ... x = 2 elseif x == 2 then ... x = 3 end end'
    into a more linear structure if patterns are simple and sequential.
    This is highly heuristic and won't fully de-flatten complex VMs.
    """
    # This is an extremely complex problem. For now, a very basic heuristic:
    # Look for sequences of 'if condition then break end' or 'if condition then goto label end'
    # that form a state machine.
    
    # Example heuristic: identify a common dispatch loop pattern
    # while l<656 do l=l+1;while l<0x392 and e%0x3fa8<0x1fd4 do l=l+1 e=(e*259)%37930 ... end end
    # A full de-flattening would require symbolic execution or AST rewriting.
    
    # Placeholder: attempt to remove simple, always-true/false jump conditions.
    # This is very speculative.
    code = re.sub(r'if\s+\(true\)\s+then\s*(goto\s+\w+|break)\s+end;', r'\1;', code)
    code = re.sub(r'if\s+\(false\)\s+then\s*.*?\s*end;', '', code)
    
    return code

def _moonsec_string_reconstruction(code: str) -> str:
    """
    Specifically targets Moonsec's string obfuscation patterns,
    like the large lookup table 'k' that uses byte escape sequences and concatenations.
    This function will try to reconstruct these strings.
    """
    # Pattern to find the large 'k' string assignment
    match = re.search(r'k=\"((?:\\x[0-9a-fA-F]{2})*|(?:\\\d{1,3})*|[^"]*)\";', code)
    if match:
        obfuscated_k = match.group(1)
        # Attempt to unescape and decode it
        decoded_k = _unescape_lua_string_safe(obfuscated_k)
        
        # Replace the original assignment with the decoded one (or a placeholder)
        code = code.replace(match.group(0), f'local k_decoded = "{decoded_k}"; -- Original k string decoded')
    
    return code

def _moonsec_anti_tamper_neutralization(code: str) -> str:
    """
    Identifies and neutralizes simple Moonsec anti-tamper mechanisms.
    (AntiDump, AntiDebug, AntiHook, AntiTrace)
    """
    # Common anti-debug/dump patterns in Lua:
    # 1. Checks for debug library functions: debug.getinfo, debug.getupvalue, debug.sethook
    # 2. Checks for environment manipulation: getfenv, setfenv
    # 3. Hooks: hookfunction (often wrapped)

    # Neutralize debug library checks (very basic - replace with 'nil' or safe function)
    code = re.sub(r'debug\.getinfo', 'nil', code)
    code = re.sub(r'debug\.getupvalue', 'nil', code)
    code = re.sub(r'debug\.sethook', 'nil', code)
    
    # Basic neutralization of require hooks (e.g., if require is re-assigned)
    code = re.sub(r'require\s*=\s*(.*?);', 'require = _G.require;', code) # Restore global require

    # Remove simple error/exit calls triggered by anti-tamper
    code = re.sub(r'if\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*then\s*error\(.*?\)\s*end;', '', code, flags=re.DOTALL)
    code = re.sub(r'if\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*then\s*os\.exit\(.*?\)\s*end;', '', code, flags=re.DOTALL)

    return code


def deobf_moonsec_v3(code: str) -> str:
    """
    Applies comprehensive heuristics for Moonsec V3 deobfuscation.
    This includes specific wrapper removal, advanced string decoding, control flow simplification,
    environment cleanup, and anti-tamper neutralization, as per the provided techniques.
    Full de-virtualization of the table-based opcode dispatcher remains a highly complex task
    that typically requires a Lua AST parser and symbolic execution.
    """
    output_messages = ["--- Moonsec V3 Deobfuscation (Comprehensive Heuristic Clean-up) ---"]
    
    original_len = len(code)
    code = _moonsec_remove_initial_wrapper(code)
    if len(code) < original_len:
        output_messages.append("- Removed initial Moonsec V3 'gsub' wrapper.")

    original_len = len(code)
    code = _moonsec_extract_main_function(code)
    if len(code) < original_len:
        output_messages.append("- Extracted main obfuscated function from 'return(function(...))' wrapper.")

    # Apply general string and escape decoding aggressively
    code = _unescape_lua_string_safe(code)
    code = _decode_hex_strings(code) # Handles %xXX
    code = _decode_base64_strings(code)
    code = _decode_xor_string_basic(code) # Apply basic XOR if pattern found
    code = _resolve_string_concatenation(code)
    output_messages.append("- Applied advanced string/escape decoding (hex, base64, xor, unicode, concatenation).")
    
    # Moonsec specific string reconstruction (e.g., the 'k' string)
    code = _moonsec_string_reconstruction(code)
    output_messages.append("- Attempted reconstruction of large obfuscated strings (e.g., 'k' string).")

    # Environment and anti-tamper cleanup
    code = _simplify_getfenv_setfenv(code)
    code = _moonsec_anti_tamper_neutralization(code)
    output_messages.append("- Cleaned up getfenv/setfenv patterns and neutralized simple anti-tamper checks.")

    # Control flow simplification and junk removal
    code = _remove_simple_dead_code(code)
    code = _moonsec_simplify_control_flow(code)
    output_messages.append("- Removed simple dead code and applied basic control flow simplification heuristics.")
    
    # Final beautification
    cleaned_code = beautify_lua(code)
    output_messages.append("- Applied final Lua code formatting (beautification).")

    output_messages.append("\nNote: Full de-virtualization (table-based opcode dispatcher) and advanced control flow "
                           "flattening require a Lua AST parser and symbolic execution, which is beyond the scope of "
                           "pure regex and string manipulation.")

    return "\n".join(output_messages) + f"\n\n{cleaned_code}"
