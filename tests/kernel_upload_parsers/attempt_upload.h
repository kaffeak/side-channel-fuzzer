/* Host-only integration adapter, never an installed kernel interface. */
#ifndef RVZR_HOST_ATTEMPT_UPLOAD_H
#define RVZR_HOST_ATTEMPT_UPLOAD_H
#include "compat.h"
#include "preparation_state.h"

#define ATTEMPT_MAX_BYTES (512 * 1024)
enum attempt_kind { ATTEMPT_TC, ATTEMPT_INPUT };
struct attempt_handle {
    /* Bind once on accepted BEGIN; token, kind, parent and length stay immutable. */
    struct rvzr_prep_attempt token;
    enum attempt_kind kind;
    rvzr_prep_u64 parent_tc;
    size_t length, position;
    bool received; /* Structural receipt only; authoritative eligibility is in prep. */
};
struct attempt_adapter {
    struct rvzr_prep_state prep;
    unsigned int fake_resources;
    bool fail_cleanup;
    size_t cleanup_calls, tc_resets, input_resets, allocations, loads;
};

void attempt_init(struct attempt_adapter *a);
int attempt_begin(struct attempt_adapter *a, struct attempt_handle *h,
                  enum attempt_kind kind, struct rvzr_prep_stamp expected,
                  rvzr_prep_u64 parent_tc, size_t length);
ssize_t attempt_feed(struct attempt_adapter *a, struct attempt_handle *h,
                     const char *bytes, size_t count);
int attempt_complete(struct attempt_adapter *a, struct attempt_handle *h);
int attempt_abort(struct attempt_adapter *a, const struct attempt_handle *h);
#endif
