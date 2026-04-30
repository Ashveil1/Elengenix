# agent_brain.py Indentation Fix Required

## Issue
The `agent_brain.py` file has widespread indentation errors in the `StrategicPlanner` class (lines 80-251). The class methods are not properly indented - they have 1-space indentation instead of the required 4-space indentation for method definitions and 8-space indentation for method bodies.

## Affected Lines
- Line 81: Class docstring (not indented)
- Line 83: `def __init__` (1-space indent, should be 4)
- Lines 84-85: `__init__` body (1-space indent, should be 8)
- Line 87: `def generate_attack_tree` (1-space indent, should be 4)
- Lines 92-151: Method body (1-space indent, should be 8)
- Line 153: `def _default_attack_tree` (1-space indent, should be 4)
- Lines 154-174: Method body (1-space indent, should be 8)
- Line 176: `def select_next_tool` (1-space indent, should be 4)
- And more...

## Fix Required
The entire `StrategicPlanner` class needs manual indentation fix. Programmatic fixes have failed due to the complexity and widespread nature of the errors.

## Recommended Action
Manually fix the indentation in `agent_brain.py` by:
1. Indenting the class docstring (line 81) with 4 spaces
2. Indenting all method definitions (lines starting with `def`) with 4 spaces
3. Indenting all method bodies with 8 spaces
4. Ensuring consistent indentation throughout the class

## Impact
This file is imported by `main.py` and causes the elengenix CLI to fail when trying to initialize the agent. The system cannot be fully tested until this is fixed.
