# Security audit: boostorg/beast

Date: 2026-11-20 | Auditor: [mutsuumii](https://github.com/mutsuumii)

## Summary

Found 10 issue(s): 10 high.

## Findings

### 1. [HIGH] Integer overflow in size calculation

**CWE-190** | `test/extern/zlib-1.3.2/zutil.c` line 302

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
return sizeof(uInt) > 2 ? (voidpf)malloc(items * size) :
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 2. [HIGH] Use-after-free pattern

**CWE-416** | `test/extern/zlib-1.3.2/zutil.c` line 247

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
farfree(ptr);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 3. [HIGH] Use-after-free pattern

**CWE-416** | `test/extern/zlib-1.3.2/zutil.c` line 284

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
_hfree(ptr);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 4. [HIGH] Use-after-free pattern

**CWE-416** | `test/extern/zlib-1.3.2/zutil.c` line 308

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(ptr);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 5. [HIGH] Missing NULL check after allocation

**CWE-476** | `test/extern/zlib-1.3.2/zutil.c` line 226

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
buf = farmalloc(bsize);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 6. [HIGH] Missing NULL check after allocation

**CWE-476** | `test/extern/zlib-1.3.2/zutil.c` line 229

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
buf = farmalloc(bsize + 16L);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 7. [HIGH] Missing NULL check after allocation

**CWE-476** | `test/extern/zlib-1.3.2/zutil.c` line 295

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
extern voidp malloc(uInt size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 8. [HIGH] Missing NULL check after allocation

**CWE-476** | `test/extern/zlib-1.3.2/zutil.c` line 296

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
extern voidp calloc(uInt items, uInt size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 9. [HIGH] Missing NULL check after allocation

**CWE-476** | `test/extern/zlib-1.3.2/zutil.c` line 303

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
(voidpf)calloc(items, size);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 10. [HIGH] Insecure random — cryptographic use

**CWE-338** | `test/bench/buffers/bench_buffers.cpp` line 140

rand() seeded with time() is predictable within seconds. Tokens or session IDs generated this way are guessable.

```
1 + (rand()%(2*size))));
```

**Fix:** Use getrandom() on Linux, /dev/urandom, or arc4random(). Never use rand() for security-sensitive values.
---
