#include <epan/epan.h>

/*
 * Compile-only smoke test for Wireshark header availability.
 *
 * Referencing epan_get_version verifies:
 *   1. <epan/epan.h> is findable in the standard include path
 *   2. epan_get_version is declared (catches mismatched/stale header versions)
 *
 * This translation unit is compiled to an object file by cc::Build::try_compile
 * and never linked or executed — safe for cross-compilation targets.
 */
typedef const char *(*epan_version_fn_t)(void);
static epan_version_fn_t _smoke_check = epan_get_version;
