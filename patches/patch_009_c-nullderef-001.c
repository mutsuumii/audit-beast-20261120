# Missing NULL check after allocation
# CWE-476 | Severity: HIGH
# File: test/extern/zlib-1.3.2/zutil.c line 303

**Risk:** Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
