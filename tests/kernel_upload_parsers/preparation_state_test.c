// SPDX-License-Identifier: MIT
// Logical tests only. No real parser, resource acquisition, cleanup or execution.
#include "preparation_state.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); exit(1); \
} } while (0)
#define OK(expression) CHECK((expression) == RVZR_PREP_OK)
#define REJECT(s, expression, expected) do { \
    struct rvzr_prep_state before_ = (s); \
    CHECK((expression) == (expected)); CHECK(equal_state(&(s), &before_)); \
} while (0)

static bool equal_state(const struct rvzr_prep_state *a, const struct rvzr_prep_state *b)
{
    // Compare fields, not unspecified structure padding.
    return a->instance.high == b->instance.high && a->instance.low == b->instance.low &&
        a->revision == b->revision && a->active_attempt == b->active_attempt &&
        a->tc_id == b->tc_id && a->input_id == b->input_id &&
        a->allocation_generation == b->allocation_generation && a->phase == b->phase;
}

static struct rvzr_prep_state fresh(void)
{
    struct rvzr_prep_state s;
    OK(rvzr_prep_init(&s, (struct rvzr_prep_instance){10, 20}));
    CHECK(s.phase == RVZR_PREP_EMPTY && s.revision == 0 && s.active_attempt == 0);
    CHECK(s.tc_id == 0 && s.input_id == 0 && s.allocation_generation == 0);
    return s;
}

static void no_execution(struct rvzr_prep_state *s)
{
    REJECT(*s, rvzr_prep_check_execution(s, rvzr_prep_identity(s)), RVZR_PREP_BAD_STATE);
}

static struct rvzr_prep_attempt start_tc(struct rvzr_prep_state *s)
{
    struct rvzr_prep_attempt attempt;
    rvzr_prep_u64 previous = s->revision;
    OK(rvzr_prep_begin_tc(s, rvzr_prep_snapshot(s), &attempt));
    CHECK(s->phase == RVZR_PREP_CLEANING && s->revision > previous);
    CHECK(attempt.id == s->revision && s->allocation_generation == attempt.id);
    CHECK(s->tc_id == 0 && s->input_id == 0);
    REJECT(*s, rvzr_prep_check_attempt(s, attempt), RVZR_PREP_BAD_STATE);
    no_execution(s);
    OK(rvzr_prep_cleanup_done(s, rvzr_prep_snapshot(s), true));
    CHECK(s->phase == RVZR_PREP_TC_RX && s->active_attempt == attempt.id);
    return attempt;
}

static struct rvzr_prep_attempt prepare_tc(struct rvzr_prep_state *s)
{
    struct rvzr_prep_attempt attempt = start_tc(s);
    OK(rvzr_prep_advance_tc(s, attempt));
    CHECK(s->phase == RVZR_PREP_TC_VALIDATE);
    OK(rvzr_prep_advance_tc(s, attempt));
    CHECK(s->phase == RVZR_PREP_TC_ALLOCATE);
    OK(rvzr_prep_advance_tc(s, attempt));
    CHECK(s->phase == RVZR_PREP_TC_LOAD);
    OK(rvzr_prep_commit_tc(s, attempt));
    CHECK(s->phase == RVZR_PREP_TC_READY && s->tc_id == attempt.id);
    CHECK(s->active_attempt == 0 && s->input_id == 0);
    return attempt;
}

static struct rvzr_prep_attempt start_input(struct rvzr_prep_state *s)
{
    struct rvzr_prep_attempt attempt;
    rvzr_prep_u64 tc = s->tc_id, allocation = s->allocation_generation;
    OK(rvzr_prep_begin_input(s, rvzr_prep_snapshot(s), tc, &attempt));
    CHECK(s->phase == RVZR_PREP_INPUT_RX && s->input_id == 0);
    CHECK(s->tc_id == tc && s->allocation_generation == allocation);
    no_execution(s);
    return attempt;
}

static struct rvzr_prep_identity prepare_all(struct rvzr_prep_state *s)
{
    prepare_tc(s);
    struct rvzr_prep_attempt attempt = start_input(s);
    OK(rvzr_prep_commit_input(s, attempt));
    CHECK(s->phase == RVZR_PREP_READY && s->input_id == attempt.id);
    CHECK(s->active_attempt == 0);
    OK(rvzr_prep_check_execution(s, rvzr_prep_identity(s)));
    return rvzr_prep_identity(s);
}

static void cleaned_failure(struct rvzr_prep_state *s)
{
    CHECK(s->phase == RVZR_PREP_CLEANING);
    CHECK(s->active_attempt == 0 && s->tc_id == 0 && s->input_id == 0);
    no_execution(s);
    OK(rvzr_prep_cleanup_done(s, rvzr_prep_snapshot(s), true));
    CHECK(s->phase == RVZR_PREP_FAILED);
    no_execution(s);
}

static void progression(void)
{
    struct rvzr_prep_state s = fresh();
    no_execution(&s);
    prepare_all(&s);
}

static void early_commit(void)
{
    struct rvzr_prep_state s = fresh();
    struct rvzr_prep_attempt a = start_tc(&s);
    for (int stage = 0; stage < 3; stage++) {
        no_execution(&s);
        REJECT(s, rvzr_prep_commit_tc(&s, a), RVZR_PREP_BAD_STATE);
        REJECT(s, rvzr_prep_commit_input(&s, a), RVZR_PREP_BAD_STATE);
        OK(rvzr_prep_advance_tc(&s, a));
    }
    REJECT(s, rvzr_prep_advance_tc(&s, a), RVZR_PREP_BAD_STATE);
    OK(rvzr_prep_commit_tc(&s, a));
    REJECT(s, rvzr_prep_commit_tc(&s, a), RVZR_PREP_STALE);
}

static void failed_tc(void)
{
    // Every receive/validation/allocation/loading failure blocks commitment.
    for (int stage = 0; stage < 4; stage++) {
        struct rvzr_prep_state s = fresh();
        struct rvzr_prep_attempt a = start_tc(&s);
        for (int i = 0; i < stage; i++)
            OK(rvzr_prep_advance_tc(&s, a));
        OK(rvzr_prep_fail(&s, a));
        REJECT(s, rvzr_prep_commit_tc(&s, a), RVZR_PREP_STALE);
        cleaned_failure(&s);
    }
}

static void failed_input(void)
{
    struct rvzr_prep_state s = fresh();
    struct rvzr_prep_identity old = prepare_all(&s);
    struct rvzr_prep_attempt a = start_input(&s);
    OK(rvzr_prep_fail(&s, a));
    CHECK(s.allocation_generation != old.allocation_generation);
    REJECT(s, rvzr_prep_commit_input(&s, a), RVZR_PREP_STALE);
    cleaned_failure(&s);
    struct rvzr_prep_attempt out;
    REJECT(s, rvzr_prep_begin_input(&s, rvzr_prep_snapshot(&s), old.tc_id, &out),
           RVZR_PREP_BAD_STATE); // Fresh TC required, never roll back to old input/TC.
}

static void abort_tc(void)
{
    struct rvzr_prep_state s = fresh();
    struct rvzr_prep_attempt a = start_tc(&s);
    OK(rvzr_prep_abort(&s, a));
    REJECT(s, rvzr_prep_abort(&s, a), RVZR_PREP_STALE);
    cleaned_failure(&s);
}

static void abort_input(void)
{
    struct rvzr_prep_state s = fresh();
    prepare_tc(&s);
    struct rvzr_prep_attempt a = start_input(&s);
    OK(rvzr_prep_abort(&s, a));
    cleaned_failure(&s);
}

static void stale_attempt(void)
{
    struct rvzr_prep_state s = fresh();
    struct rvzr_prep_attempt a = start_tc(&s), stale = a;
    stale.id++;
    REJECT(s, rvzr_prep_check_attempt(&s, stale), RVZR_PREP_STALE);
    REJECT(s, rvzr_prep_advance_tc(&s, stale), RVZR_PREP_STALE);
    REJECT(s, rvzr_prep_commit_tc(&s, stale), RVZR_PREP_STALE);
    REJECT(s, rvzr_prep_fail(&s, stale), RVZR_PREP_STALE);
    stale.id = 0;
    REJECT(s, rvzr_prep_abort(&s, stale), RVZR_PREP_STALE);
    OK(rvzr_prep_check_attempt(&s, a));
}

static void delayed_operation(void)
{
    struct rvzr_prep_state s = fresh();
    struct rvzr_prep_attempt a = start_tc(&s);
    OK(rvzr_prep_abort(&s, a));
    struct rvzr_prep_stamp old_cleanup = rvzr_prep_snapshot(&s);
    cleaned_failure(&s);
    struct rvzr_prep_attempt b = start_tc(&s);
    CHECK(b.id > a.id);
    REJECT(s, rvzr_prep_check_attempt(&s, a), RVZR_PREP_STALE);
    REJECT(s, rvzr_prep_abort(&s, a), RVZR_PREP_STALE);
    REJECT(s, rvzr_prep_commit_tc(&s, a), RVZR_PREP_STALE);
    REJECT(s, rvzr_prep_cleanup_done(&s, old_cleanup, false), RVZR_PREP_STALE);
    OK(rvzr_prep_check_attempt(&s, b));
}

// This ledger is deliberately test-only. Zero bits and reset=true are claims,
// not proof that pages, permissions, PTEs or parser state were really cleaned.
struct fake_ownership { unsigned int owned; bool parsers_reset; };
static bool ledger_safe(struct fake_ownership ledger)
{
    return ledger.owned == 0 && ledger.parsers_reset;
}

static void clean_retry(void)
{
    struct rvzr_prep_state s = fresh();
    struct rvzr_prep_attempt a = start_tc(&s);
    OK(rvzr_prep_advance_tc(&s, a));
    OK(rvzr_prep_advance_tc(&s, a));
    struct fake_ownership ledger = {7, false};
    OK(rvzr_prep_fail(&s, a));
    struct rvzr_prep_attempt out;
    REJECT(s, rvzr_prep_begin_tc(&s, rvzr_prep_snapshot(&s), &out), RVZR_PREP_BAD_STATE);
    CHECK(!ledger_safe(ledger));
    ledger.owned = 0;
    CHECK(!ledger_safe(ledger));
    ledger.parsers_reset = true;
    OK(rvzr_prep_cleanup_done(&s, rvzr_prep_snapshot(&s), ledger_safe(ledger)));
    CHECK(s.phase == RVZR_PREP_FAILED);
    prepare_all(&s);
}

static void unsafe_cleanup(void)
{
    const struct fake_ownership ledgers[] = {{1, true}, {0, false}};
    for (unsigned int i = 0; i < sizeof(ledgers) / sizeof(ledgers[0]); i++) {
        struct rvzr_prep_state s = fresh();
        struct rvzr_prep_attempt a = start_tc(&s);
        OK(rvzr_prep_fail(&s, a));
        OK(rvzr_prep_cleanup_done(&s, rvzr_prep_snapshot(&s), ledger_safe(ledgers[i])));
        CHECK(s.phase == RVZR_PREP_UNRECOVERABLE);
        CHECK(s.active_attempt == 0 && s.tc_id == 0 && s.input_id == 0);
    }
}

static void fatal_rejection(void)
{
    struct rvzr_prep_state s = fresh();
    struct rvzr_prep_attempt a, out = {{99, 99}, 99};
    OK(rvzr_prep_begin_tc(&s, rvzr_prep_snapshot(&s), &a));
    OK(rvzr_prep_cleanup_done(&s, rvzr_prep_snapshot(&s), false));
    REJECT(s, rvzr_prep_begin_tc(&s, rvzr_prep_snapshot(&s), &out), RVZR_PREP_FATAL);
    REJECT(s, rvzr_prep_begin_input(&s, rvzr_prep_snapshot(&s), 1, &out), RVZR_PREP_FATAL);
    CHECK(out.id == 99 && out.instance.high == 99 && out.instance.low == 99);
    REJECT(s, rvzr_prep_commit_tc(&s, a), RVZR_PREP_FATAL);
    REJECT(s, rvzr_prep_commit_input(&s, a), RVZR_PREP_FATAL);
    REJECT(s, rvzr_prep_advance_tc(&s, a), RVZR_PREP_FATAL);
    REJECT(s, rvzr_prep_abort(&s, a), RVZR_PREP_FATAL);
    REJECT(s, rvzr_prep_fail(&s, a), RVZR_PREP_FATAL);
    REJECT(s, rvzr_prep_check_attempt(&s, a), RVZR_PREP_FATAL);
    REJECT(s, rvzr_prep_cleanup_done(&s, rvzr_prep_snapshot(&s), true), RVZR_PREP_FATAL);
    REJECT(s, rvzr_prep_check_execution(&s, rvzr_prep_identity(&s)), RVZR_PREP_FATAL);
}

static void identifiers(void)
{
    struct rvzr_prep_state s = fresh();
    rvzr_prep_u64 previous = 0;
    for (int i = 0; i < 32; i++) {
        struct rvzr_prep_identity id = prepare_all(&s);
        CHECK(id.tc_id > previous && id.input_id > id.tc_id);
        CHECK(id.allocation_generation == id.tc_id && s.revision > id.input_id);
        previous = s.revision;
    }
}

static void overflow(void)
{
    // Seed the boundary instead of attempting 2^64 transitions. Each mutator
    // must take the same terminal overflow path; no successful token uses MAX.
    const rvzr_prep_u64 maximum = ~(rvzr_prep_u64)0;
    for (int operation = 0; operation < 8; operation++) {
        struct rvzr_prep_state s = fresh();
        struct rvzr_prep_attempt a = {{0, 0}, 0}, out = {{99, 99}, 99};
        if (operation == 1 || operation == 4 || operation == 5)
            a = start_tc(&s);
        if (operation == 2) {
            a = start_tc(&s);
            for (int i = 0; i < 3; i++)
                OK(rvzr_prep_advance_tc(&s, a));
        }
        if (operation == 3 || operation == 6) {
            prepare_tc(&s);
            if (operation == 3)
                a = start_input(&s);
        }
        if (operation == 7)
            OK(rvzr_prep_begin_tc(&s, rvzr_prep_snapshot(&s), &a));
        s.revision = maximum - 1; // Test boundary injection, never production use.
        enum rvzr_prep_result result;
        switch (operation) {
        case 0: result = rvzr_prep_begin_tc(&s, rvzr_prep_snapshot(&s), &out); break;
        case 1: result = rvzr_prep_advance_tc(&s, a); break;
        case 2: result = rvzr_prep_commit_tc(&s, a); break;
        case 3: result = rvzr_prep_commit_input(&s, a); break;
        case 4: result = rvzr_prep_abort(&s, a); break;
        case 5: result = rvzr_prep_fail(&s, a); break;
        case 6: result = rvzr_prep_begin_input(&s, rvzr_prep_snapshot(&s), s.tc_id, &out); break;
        default: result = rvzr_prep_cleanup_done(&s, rvzr_prep_snapshot(&s), true); break;
        }
        CHECK(result == RVZR_PREP_EXHAUSTED && s.revision == maximum);
        CHECK(s.phase == RVZR_PREP_UNRECOVERABLE && s.allocation_generation == maximum);
        CHECK(s.active_attempt == 0 && s.tc_id == 0 && s.input_id == 0);
        CHECK(out.id == 99 && out.instance.high == 99 && out.instance.low == 99);
        REJECT(s, rvzr_prep_commit_tc(&s, a), RVZR_PREP_FATAL);
        REJECT(s, rvzr_prep_check_execution(&s, rvzr_prep_identity(&s)), RVZR_PREP_FATAL);
    }
    struct rvzr_prep_state s = fresh();
    s.revision = maximum - 2;
    struct rvzr_prep_attempt a;
    OK(rvzr_prep_begin_tc(&s, rvzr_prep_snapshot(&s), &a));
    CHECK(a.id == maximum - 1);
    CHECK(rvzr_prep_cleanup_done(&s, rvzr_prep_snapshot(&s), true) == RVZR_PREP_EXHAUSTED);
}

static void uncommitted_input(void)
{
    struct rvzr_prep_state s = fresh();
    prepare_tc(&s);
    no_execution(&s);
    struct rvzr_prep_attempt a = start_input(&s);
    struct rvzr_prep_identity guessed = rvzr_prep_identity(&s);
    guessed.input_id = a.id;
    REJECT(s, rvzr_prep_check_execution(&s, guessed), RVZR_PREP_BAD_STATE);
    OK(rvzr_prep_commit_input(&s, a));
    OK(rvzr_prep_check_execution(&s, guessed));
    REJECT(s, rvzr_prep_commit_input(&s, a), RVZR_PREP_STALE);
}

static void newer_state(void)
{
    struct rvzr_prep_state s = fresh();
    prepare_tc(&s);
    struct rvzr_prep_attempt old = start_input(&s);
    OK(rvzr_prep_abort(&s, old));
    struct rvzr_prep_stamp old_ticket = rvzr_prep_snapshot(&s);
    cleaned_failure(&s);
    struct rvzr_prep_identity current = prepare_all(&s);
    REJECT(s, rvzr_prep_fail(&s, old), RVZR_PREP_STALE);
    REJECT(s, rvzr_prep_commit_input(&s, old), RVZR_PREP_STALE);
    REJECT(s, rvzr_prep_cleanup_done(&s, old_ticket, false), RVZR_PREP_STALE);
    struct rvzr_prep_attempt out = {{99, 99}, 99};
    REJECT(s, rvzr_prep_begin_tc(&s, old_ticket, &out), RVZR_PREP_STALE);
    CHECK(out.id == 99);
    OK(rvzr_prep_check_execution(&s, current));
}

static void wrong_identity(void)
{
    struct rvzr_prep_state s = fresh();
    struct rvzr_prep_identity current = prepare_all(&s), wrong = current;
    wrong.tc_id++;
    REJECT(s, rvzr_prep_check_execution(&s, wrong), RVZR_PREP_STALE);
    wrong = current;
    wrong.input_id++;
    REJECT(s, rvzr_prep_check_execution(&s, wrong), RVZR_PREP_STALE);
    wrong = current;
    wrong.allocation_generation++;
    REJECT(s, rvzr_prep_check_execution(&s, wrong), RVZR_PREP_STALE);
    wrong = current;
    wrong.instance.low++;
    REJECT(s, rvzr_prep_check_execution(&s, wrong), RVZR_PREP_STALE);
}

static void wrong_instance(void)
{
    struct rvzr_prep_state s = fresh();
    struct rvzr_prep_stamp expected = rvzr_prep_snapshot(&s);
    expected.instance.high++;
    struct rvzr_prep_attempt out = {{99, 99}, 99};
    REJECT(s, rvzr_prep_begin_tc(&s, expected, &out), RVZR_PREP_STALE);
    CHECK(out.id == 99 && out.instance.high == 99 && out.instance.low == 99);
    struct rvzr_prep_attempt a = start_tc(&s);
    a.instance.low++;
    REJECT(s, rvzr_prep_advance_tc(&s, a), RVZR_PREP_STALE);
    expected = rvzr_prep_snapshot(&s);
    expected.instance.high++;
    REJECT(s, rvzr_prep_cleanup_done(&s, expected, true), RVZR_PREP_STALE);
}

static void replace_tc(void)
{
    struct rvzr_prep_state s = fresh();
    struct rvzr_prep_identity old = prepare_all(&s);
    struct rvzr_prep_attempt a;
    OK(rvzr_prep_begin_tc(&s, rvzr_prep_snapshot(&s), &a));
    CHECK(s.phase == RVZR_PREP_CLEANING && s.tc_id == 0 && s.input_id == 0);
    CHECK(s.allocation_generation != old.allocation_generation);
    no_execution(&s);
    OK(rvzr_prep_cleanup_done(&s, rvzr_prep_snapshot(&s), true));
    OK(rvzr_prep_fail(&s, a));
    cleaned_failure(&s);
    no_execution(&s); // No restoration of the previous executable tuple.
}

static void replace_input(void)
{
    struct rvzr_prep_state s = fresh();
    struct rvzr_prep_identity old = prepare_all(&s);
    struct rvzr_prep_attempt out;
    REJECT(s, rvzr_prep_begin_input(&s, rvzr_prep_snapshot(&s), old.tc_id + 1, &out),
           RVZR_PREP_STALE);
    struct rvzr_prep_attempt a = start_input(&s);
    OK(rvzr_prep_commit_input(&s, a));
    CHECK(s.tc_id == old.tc_id && s.allocation_generation == old.allocation_generation);
    CHECK(s.input_id != old.input_id);
    REJECT(s, rvzr_prep_check_execution(&s, old), RVZR_PREP_STALE);
}

static void rejected_operations(void)
{
    struct rvzr_prep_state s = fresh();
    struct rvzr_prep_attempt out = {{99, 99}, 99};
    REJECT(s, rvzr_prep_init(&s, (struct rvzr_prep_instance){0, 0}), RVZR_PREP_INVALID);
    REJECT(s, rvzr_prep_begin_tc(&s, rvzr_prep_snapshot(&s), NULL), RVZR_PREP_INVALID);
    REJECT(s, rvzr_prep_begin_input(&s, rvzr_prep_snapshot(&s), 1, &out), RVZR_PREP_BAD_STATE);
    REJECT(s, rvzr_prep_cleanup_done(&s, rvzr_prep_snapshot(&s), true), RVZR_PREP_BAD_STATE);
    struct rvzr_prep_attempt a = start_tc(&s);
    REJECT(s, rvzr_prep_begin_tc(&s, rvzr_prep_snapshot(&s), &out), RVZR_PREP_BAD_STATE);
    REJECT(s, rvzr_prep_begin_input(&s, rvzr_prep_snapshot(&s), 1, &out), RVZR_PREP_BAD_STATE);
    CHECK(out.id == 99 && out.instance.high == 99 && out.instance.low == 99);
    OK(rvzr_prep_abort(&s, a));
    struct rvzr_prep_stamp ticket = rvzr_prep_snapshot(&s);
    OK(rvzr_prep_cleanup_done(&s, ticket, true));
    REJECT(s, rvzr_prep_cleanup_done(&s, ticket, true), RVZR_PREP_STALE);
}

int main(int argc, char **argv)
{
    static const struct { const char *name; void (*run)(void); } cases[] = {
        {"progression", progression}, {"early_commit", early_commit},
        {"failed_tc", failed_tc}, {"failed_input", failed_input},
        {"abort_tc", abort_tc}, {"abort_input", abort_input},
        {"stale_attempt", stale_attempt}, {"delayed_operation", delayed_operation},
        {"clean_retry", clean_retry}, {"unsafe_cleanup", unsafe_cleanup},
        {"fatal_rejection", fatal_rejection}, {"identifiers", identifiers},
        {"overflow", overflow}, {"uncommitted_input", uncommitted_input},
        {"newer_state", newer_state}, {"wrong_identity", wrong_identity},
        {"wrong_instance", wrong_instance}, {"replace_tc", replace_tc},
        {"replace_input", replace_input}, {"rejected_operations", rejected_operations}
    };
    if (argc == 2) {
        for (unsigned int i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            if (strcmp(argv[1], cases[i].name) == 0) {
                cases[i].run();
                printf("PASS %s\n", cases[i].name);
                return 0;
            }
        }
    }
    fputs("expected one known bounded scenario\n", stderr);
    return 2;
}
