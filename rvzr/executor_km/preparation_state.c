// SPDX-License-Identifier: MIT
// Pure state/identity component. Intentionally absent from the module Makefile.
#include "preparation_state.h"

static bool same_instance(struct rvzr_prep_instance a, struct rvzr_prep_instance b)
{
    return a.high == b.high && a.low == b.low;
}

static void withdraw(struct rvzr_prep_state *s)
{
    s->active_attempt = 0;
    s->tc_id = 0;
    s->input_id = 0;
    s->allocation_generation = s->revision;
}

static enum rvzr_prep_result advance_revision(struct rvzr_prep_state *s)
{
    const rvzr_prep_u64 maximum = ~(rvzr_prep_u64)0;
    if (s->revision >= maximum - 1) {
        s->revision = maximum;
        withdraw(s);
        s->phase = RVZR_PREP_UNRECOVERABLE;
        return RVZR_PREP_EXHAUSTED;
    }
    s->revision++;
    return RVZR_PREP_OK;
}

static enum rvzr_prep_result check_stamp(const struct rvzr_prep_state *s,
                                         struct rvzr_prep_stamp stamp)
{
    if (!s)
        return RVZR_PREP_INVALID;
    if (s->phase == RVZR_PREP_UNRECOVERABLE)
        return RVZR_PREP_FATAL;
    if (!same_instance(s->instance, stamp.instance) || s->revision != stamp.revision)
        return RVZR_PREP_STALE;
    return RVZR_PREP_OK;
}

enum rvzr_prep_result rvzr_prep_init(struct rvzr_prep_state *s,
                                   struct rvzr_prep_instance instance)
{
    if (!s || !(instance.high | instance.low))
        return RVZR_PREP_INVALID;
    *s = (struct rvzr_prep_state){.instance = instance, .phase = RVZR_PREP_EMPTY};
    return RVZR_PREP_OK;
}

struct rvzr_prep_stamp rvzr_prep_snapshot(const struct rvzr_prep_state *s)
{
    return (struct rvzr_prep_stamp){s->instance, s->revision};
}

struct rvzr_prep_identity rvzr_prep_identity(const struct rvzr_prep_state *s)
{
    return (struct rvzr_prep_identity){s->instance, s->tc_id, s->input_id,
                                      s->allocation_generation};
}

enum rvzr_prep_result rvzr_prep_begin_tc(struct rvzr_prep_state *s,
    struct rvzr_prep_stamp expected, struct rvzr_prep_attempt *attempt)
{
    enum rvzr_prep_result result = check_stamp(s, expected);
    if (!attempt)
        return RVZR_PREP_INVALID;
    if (result != RVZR_PREP_OK)
        return result;
    if (s->phase != RVZR_PREP_EMPTY && s->phase != RVZR_PREP_FAILED &&
        s->phase != RVZR_PREP_TC_READY && s->phase != RVZR_PREP_READY)
        return RVZR_PREP_BAD_STATE;
    result = advance_revision(s);
    if (result != RVZR_PREP_OK)
        return result;
    withdraw(s);
    s->active_attempt = s->revision;
    s->phase = RVZR_PREP_CLEANING;
    *attempt = (struct rvzr_prep_attempt){s->instance, s->active_attempt};
    return RVZR_PREP_OK;
}

enum rvzr_prep_result rvzr_prep_begin_input(struct rvzr_prep_state *s,
    struct rvzr_prep_stamp expected, rvzr_prep_u64 parent_tc,
    struct rvzr_prep_attempt *attempt)
{
    enum rvzr_prep_result result = check_stamp(s, expected);
    if (!attempt)
        return RVZR_PREP_INVALID;
    if (result != RVZR_PREP_OK)
        return result;
    if (s->phase != RVZR_PREP_TC_READY && s->phase != RVZR_PREP_READY)
        return RVZR_PREP_BAD_STATE;
    if (!parent_tc || parent_tc != s->tc_id)
        return RVZR_PREP_STALE;
    result = advance_revision(s);
    if (result != RVZR_PREP_OK)
        return result;
    s->active_attempt = s->revision;
    s->input_id = 0;
    s->phase = RVZR_PREP_INPUT_RX;
    *attempt = (struct rvzr_prep_attempt){s->instance, s->active_attempt};
    return RVZR_PREP_OK;
}

enum rvzr_prep_result rvzr_prep_check_attempt(const struct rvzr_prep_state *s,
                                            struct rvzr_prep_attempt attempt)
{
    if (!s)
        return RVZR_PREP_INVALID;
    if (s->phase == RVZR_PREP_UNRECOVERABLE)
        return RVZR_PREP_FATAL;
    if (!same_instance(s->instance, attempt.instance) || !attempt.id ||
        s->active_attempt != attempt.id)
        return RVZR_PREP_STALE;
    if (s->phase != RVZR_PREP_TC_RX && s->phase != RVZR_PREP_TC_VALIDATE &&
        s->phase != RVZR_PREP_TC_ALLOCATE && s->phase != RVZR_PREP_TC_LOAD &&
        s->phase != RVZR_PREP_INPUT_RX)
        return RVZR_PREP_BAD_STATE;
    return RVZR_PREP_OK;
}

enum rvzr_prep_result rvzr_prep_advance_tc(struct rvzr_prep_state *s,
                                         struct rvzr_prep_attempt attempt)
{
    enum rvzr_prep_result result = rvzr_prep_check_attempt(s, attempt);
    if (result != RVZR_PREP_OK)
        return result;
    if (s->phase != RVZR_PREP_TC_RX && s->phase != RVZR_PREP_TC_VALIDATE &&
        s->phase != RVZR_PREP_TC_ALLOCATE)
        return RVZR_PREP_BAD_STATE;
    result = advance_revision(s);
    if (result != RVZR_PREP_OK)
        return result;
    switch (s->phase) {
    case RVZR_PREP_TC_RX: s->phase = RVZR_PREP_TC_VALIDATE; break;
    case RVZR_PREP_TC_VALIDATE: s->phase = RVZR_PREP_TC_ALLOCATE; break;
    default: s->phase = RVZR_PREP_TC_LOAD; break;
    }
    return RVZR_PREP_OK;
}

enum rvzr_prep_result rvzr_prep_commit_tc(struct rvzr_prep_state *s,
                                        struct rvzr_prep_attempt attempt)
{
    enum rvzr_prep_result result = rvzr_prep_check_attempt(s, attempt);
    if (result != RVZR_PREP_OK)
        return result;
    if (s->phase != RVZR_PREP_TC_LOAD)
        return RVZR_PREP_BAD_STATE;
    result = advance_revision(s);
    if (result != RVZR_PREP_OK)
        return result;
    s->tc_id = s->active_attempt;
    s->active_attempt = 0;
    s->phase = RVZR_PREP_TC_READY;
    return RVZR_PREP_OK;
}

enum rvzr_prep_result rvzr_prep_commit_input(struct rvzr_prep_state *s,
                                           struct rvzr_prep_attempt attempt)
{
    enum rvzr_prep_result result = rvzr_prep_check_attempt(s, attempt);
    if (result != RVZR_PREP_OK)
        return result;
    if (s->phase != RVZR_PREP_INPUT_RX)
        return RVZR_PREP_BAD_STATE;
    result = advance_revision(s);
    if (result != RVZR_PREP_OK)
        return result;
    s->input_id = s->active_attempt;
    s->active_attempt = 0;
    s->phase = RVZR_PREP_READY;
    return RVZR_PREP_OK;
}

enum rvzr_prep_result rvzr_prep_abort(struct rvzr_prep_state *s,
                                    struct rvzr_prep_attempt attempt)
{
    enum rvzr_prep_result result = rvzr_prep_check_attempt(s, attempt);
    if (result != RVZR_PREP_OK)
        return result;
    result = advance_revision(s);
    if (result != RVZR_PREP_OK)
        return result;
    withdraw(s);
    s->phase = RVZR_PREP_CLEANING;
    return RVZR_PREP_OK;
}

enum rvzr_prep_result rvzr_prep_fail(struct rvzr_prep_state *s,
                                   struct rvzr_prep_attempt attempt)
{
    return rvzr_prep_abort(s, attempt);
}

enum rvzr_prep_result rvzr_prep_cleanup_done(struct rvzr_prep_state *s,
    struct rvzr_prep_stamp ticket, bool safe)
{
    enum rvzr_prep_result result = check_stamp(s, ticket);
    if (result != RVZR_PREP_OK)
        return result;
    if (s->phase != RVZR_PREP_CLEANING)
        return RVZR_PREP_BAD_STATE;
    result = advance_revision(s);
    if (result != RVZR_PREP_OK)
        return result;
    if (!safe) {
        withdraw(s);
        s->phase = RVZR_PREP_UNRECOVERABLE;
    } else {
        s->phase = s->active_attempt ? RVZR_PREP_TC_RX : RVZR_PREP_FAILED;
    }
    return RVZR_PREP_OK;
}

enum rvzr_prep_result rvzr_prep_check_execution(const struct rvzr_prep_state *s,
                                              struct rvzr_prep_identity expected)
{
    if (!s)
        return RVZR_PREP_INVALID;
    if (s->phase == RVZR_PREP_UNRECOVERABLE)
        return RVZR_PREP_FATAL;
    if (s->phase != RVZR_PREP_READY)
        return RVZR_PREP_BAD_STATE;
    if (!same_instance(s->instance, expected.instance) || !expected.tc_id ||
        !expected.input_id || !expected.allocation_generation ||
        expected.tc_id != s->tc_id || expected.input_id != s->input_id ||
        expected.allocation_generation != s->allocation_generation)
        return RVZR_PREP_STALE;
    return RVZR_PREP_OK;
}
