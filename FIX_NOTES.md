# Fix 5 test failures in test_elengix_agent_memory.py

## Issues:
1-2. test_stores_reasoning, test_stores_tool_result - `call(...).kwargs["content"]` returns `ANY` not actual content
3. test_no_vector - expects mock_learning.remember.called but it won't be since _learning was never set
4. test_stores_report_summary - same ANY pattern issue  
5. test_post_step_long_reasoning_truncated - "Reasoning: " is 11 chars not 10, assert <= 311 not 310
