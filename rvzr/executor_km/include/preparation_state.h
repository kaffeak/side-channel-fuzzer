// SPDX-License-Identifier: MIT
// Passive lifecycle logic: not in Kbuild and not an execution/security gate.
#ifndef RVZR_PREPARATION_STATE_H
#define RVZR_PREPARATION_STATE_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef u64 rvzr_prep_u64;
#else
#include <stdbool.h>
#include <stdint.h>
typedef uint64_t rvzr_prep_u64;
#endif

enum rvzr_prep_phase {
    RVZR_PREP_EMPTY, RVZR_PREP_CLEANING, RVZR_PREP_TC_RX, RVZR_PREP_TC_VALIDATE,
    RVZR_PREP_TC_ALLOCATE, RVZR_PREP_TC_LOAD, RVZR_PREP_TC_READY,
    RVZR_PREP_INPUT_RX, RVZR_PREP_READY, RVZR_PREP_FAILED, RVZR_PREP_UNRECOVERABLE
};

enum rvzr_prep_result {
    RVZR_PREP_OK, RVZR_PREP_INVALID, RVZR_PREP_STALE, RVZR_PREP_BAD_STATE,
    RVZR_PREP_FATAL, RVZR_PREP_EXHAUSTED
};

struct rvzr_prep_instance { rvzr_prep_u64 high, low; };
struct rvzr_prep_stamp { struct rvzr_prep_instance instance; rvzr_prep_u64 revision; };
struct rvzr_prep_attempt { struct rvzr_prep_instance instance; rvzr_prep_u64 id; };
struct rvzr_prep_identity {
    struct rvzr_prep_instance instance;
    rvzr_prep_u64 tc_id, input_id, allocation_generation;
};

// Treat members as read-only outside this component. No atomics or locks: caller
// must serialize all operations and snapshot access in any future integration.
struct rvzr_prep_state {
    struct rvzr_prep_instance instance;
    rvzr_prep_u64 revision, active_attempt, tc_id, input_id, allocation_generation;
    enum rvzr_prep_phase phase;
};

// Constructor for fresh storage ONLY; caller supplies a new, nonzero instance.
// Reinitializing a live/fatal instance is not a supported recovery operation.
enum rvzr_prep_result rvzr_prep_init(struct rvzr_prep_state *s,
                                   struct rvzr_prep_instance instance);
// Accessors require a nonnull initialized state. Returned values are snapshots,
// not leases; identity may contain zero/uncommitted IDs outside READY.
struct rvzr_prep_stamp rvzr_prep_snapshot(const struct rvzr_prep_state *s);
struct rvzr_prep_identity rvzr_prep_identity(const struct rvzr_prep_state *s);

// Begin returns a reserved token. TC reception cannot start until cleanup_done.
// Input begin retains only its named TC; caller must actually reset its parser.
enum rvzr_prep_result rvzr_prep_begin_tc(struct rvzr_prep_state *s,
    struct rvzr_prep_stamp expected, struct rvzr_prep_attempt *attempt);
enum rvzr_prep_result rvzr_prep_begin_input(struct rvzr_prep_state *s,
    struct rvzr_prep_stamp expected, rvzr_prep_u64 parent_tc,
    struct rvzr_prep_attempt *attempt);
enum rvzr_prep_result rvzr_prep_check_attempt(const struct rvzr_prep_state *s,
                                            struct rvzr_prep_attempt attempt);
// Acknowledge success of RX, VALIDATE, ALLOCATE, respectively. Commit acknowledges
// successful loading of ALL code. These acknowledge evidence supplied by caller;
// no parser, allocation, validation or loading work is performed here.
enum rvzr_prep_result rvzr_prep_advance_tc(struct rvzr_prep_state *s,
                                         struct rvzr_prep_attempt attempt);
enum rvzr_prep_result rvzr_prep_commit_tc(struct rvzr_prep_state *s,
                                        struct rvzr_prep_attempt attempt);
// Acknowledges complete, validated, parent-associated input, not just byte count.
enum rvzr_prep_result rvzr_prep_commit_input(struct rvzr_prep_state *s,
                                           struct rvzr_prep_attempt attempt);
// Both revoke the WHOLE accepted preparation; no rollback. Error/reason logging
// remains with the caller. Snapshot after success supplies the cleanup ticket.
enum rvzr_prep_result rvzr_prep_abort(struct rvzr_prep_state *s,
                                    struct rvzr_prep_attempt attempt);
enum rvzr_prep_result rvzr_prep_fail(struct rvzr_prep_state *s,
                                   struct rvzr_prep_attempt attempt);
// safe=true attests full required cleanup AND parser reset, not merely !receiving.
// No real resources are tracked/released. A stale cleanup ticket has no effect.
enum rvzr_prep_result rvzr_prep_cleanup_done(struct rvzr_prep_state *s,
    struct rvzr_prep_stamp ticket, bool safe);
enum rvzr_prep_result rvzr_prep_check_execution(const struct rvzr_prep_state *s,
                                              struct rvzr_prep_identity expected);

// INVALID/STALE/BAD_STATE/FATAL leave state and output arguments unchanged.
// EXHAUSTED is a deliberate, complete fail-closed transition: UINT64_MAX is
// reserved as the terminal revision, identities revoked, resources quarantined
// by the FUTURE caller. It never wraps or purports to have performed cleanup.
#endif
