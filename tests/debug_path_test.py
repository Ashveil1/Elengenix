def test_debug_path():
    import os, sys
    print('CWD:', os.getcwd())
    print('sys.path first entries:', sys.path[:5])
