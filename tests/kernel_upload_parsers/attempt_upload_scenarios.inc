/* Fixed host integration scenarios, included only by harness.c to reuse its
 * exact allocation registry, parser-call wrappers and bounded payload checks.
 */
#define REQUIRE(x) do { if (!(x)) fatal("attempt scenario: " #x); } while (0)
static const char *attempt_tc_path, *attempt_input_path, *attempt_alternate_path;
static const char *attempt_bad_tc_path, *attempt_bad_input_path, *attempt_expected_path;
static const char *attempt_expected_tc_path;

static const char *attempt_phase(const struct attempt_adapter *a)
{
    switch (a->prep.phase) {
    case RVZR_PREP_READY: return "READY";
    case RVZR_PREP_TC_READY: return "TC_READY";
    case RVZR_PREP_FAILED: return "FAILED";
    case RVZR_PREP_UNRECOVERABLE: return "UNRECOVERABLE";
    default: return "in-progress";
    }
}

static size_t attempt_file_size(const char *path)
{
    char data[MAX_FILE];
    return read_fixture(path, data);
}

static struct attempt_handle begin_file(struct attempt_adapter *a, const char *path,
                                        enum attempt_kind kind)
{
    struct attempt_handle h = {0};
    size_t tc_resets = a->tc_resets, input_resets = a->input_resets;
    REQUIRE(attempt_begin(a, &h, kind, rvzr_prep_snapshot(&a->prep),
                          kind == ATTEMPT_INPUT ? a->prep.tc_id : 0,
                          attempt_file_size(path)) == 0);
    REQUIRE(a->input_resets == input_resets + 1 && host_input_idle());
    REQUIRE(a->tc_resets == tc_resets + (kind == ATTEMPT_TC));
    if (kind == ATTEMPT_TC) REQUIRE(host_tc_idle() && a->prep.phase == RVZR_PREP_TC_RX);
    else REQUIRE(a->prep.phase == RVZR_PREP_INPUT_RX && n_actors == 1);
    printf("{\"event\":\"begin\",\"kind\":%d,\"attempt\":%llu,\"revision\":%llu,"
           "\"tc_resets\":%zu,\"input_resets\":%zu}\n", kind, h.token.id, a->prep.revision,
           a->tc_resets, a->input_resets);
    return h;
}

static ssize_t drive_attempt(struct attempt_adapter *a, struct attempt_handle *h,
                             const char *path, size_t target)
{
    char data[MAX_FILE];
    size_t length = read_fixture(path, data);
    REQUIRE(target <= length && target <= h->length && target >= h->position);
    ssize_t ret = 0;
    use_inputs = h->kind == ATTEMPT_INPUT;
    while (h->position < target) {
        size_t count = target - h->position;
        if (count > PAGE_SIZE) count = PAGE_SIZE;
        size_t previous = h->position, before_calls = parser_calls;
        ret = attempt_feed(a, h, data + previous, count);
        printf("{\"event\":\"attempt_feed\",\"kind\":%d,\"requested\":%zu,\"ret\":%zd,"
               "\"before\":%zu,\"position\":%zu,\"calls_before\":%zu,\"calls_after\":%zu,"
               "\"parser_ret\":%zd,\"parser_finished\":%s,\"state\":\"%s\"}\n",
               h->kind, count, ret, previous, h->position, before_calls, parser_calls,
               last_parser_ret, last_finished ? "true" : "false", attempt_phase(a));
        fflush(stdout);
        REQUIRE(parser_calls == before_calls + 1);
        if (ret < 0) {
            REQUIRE(h->position == previous || (last_parser_ret > 0 &&
                    h->position == previous + (size_t)last_parser_ret));
            return ret;
        }
        REQUIRE(ret > 0 && (size_t)ret <= count && h->position == previous + (size_t)ret);
    }
    return ret;
}

static struct attempt_handle prepared_tc(struct attempt_adapter *a)
{
    struct attempt_handle h = begin_file(a, attempt_tc_path, ATTEMPT_TC);
    REQUIRE(drive_attempt(a, &h, attempt_tc_path, h.length) > 0);
    compare_reset_payload(attempt_expected_tc_path);
    REQUIRE(a->prep.tc_id == 0 && a->prep.input_id == 0);
    REQUIRE(attempt_complete(a, &h) == 0 && a->prep.phase == RVZR_PREP_TC_READY);
    return h;
}

static struct attempt_handle prepared_input(struct attempt_adapter *a)
{
    struct attempt_handle h = begin_file(a, attempt_alternate_path, ATTEMPT_INPUT);
    REQUIRE(drive_attempt(a, &h, attempt_alternate_path, h.length) > 0);
    REQUIRE(rvzr_prep_check_execution(&a->prep, rvzr_prep_identity(&a->prep)) != RVZR_PREP_OK);
    REQUIRE(attempt_complete(a, &h) == 0);
    REQUIRE(rvzr_prep_check_execution(&a->prep, rvzr_prep_identity(&a->prep)) == RVZR_PREP_OK);
    use_inputs = true;
    compare_reset_payload(attempt_expected_path); // Independent byte-for-byte comparison.
    return h;
}

struct attempt_observation { uint64_t words[32]; unsigned char prefix[4096]; };
static struct attempt_observation observe_attempt(const struct attempt_adapter *a,
                                                  const struct attempt_handle *h, size_t prefix)
{
    struct attempt_observation o = {0};
    const uint64_t words[] = {
        a->prep.instance.high, a->prep.instance.low, a->prep.revision, a->prep.active_attempt,
        a->prep.tc_id, a->prep.input_id, a->prep.allocation_generation, a->prep.phase,
        parser_calls, host_tc_cursor(), host_input_cursor(), n_actors, n_inputs,
        a->fake_resources, a->cleanup_calls, a->tc_resets, a->input_resets,
        a->allocations, a->loads, live_bytes, total_attempts,
        h->position, h->length, h->received, h->token.id, h->kind, h->parent_tc,
        h->token.instance.high, h->token.instance.low, (size_t)inputs, (size_t)test_case
    };
    _Static_assert(sizeof(words) <= sizeof(o.words), "observation capacity");
    memcpy(o.words, words, sizeof(words));
    REQUIRE(prefix <= sizeof(o.prefix));
    if (prefix) {
        // Callers request only a prefix already written by real parsing. Never
        // inspect unwritten RDBF allocation tails or incomplete metadata.
        const void *data;
        if (h->kind == ATTEMPT_INPUT) {
            REQUIRE(tracked(inputs, sizeof(*inputs)) && prefix <= inputs->data_size);
            data = inputs->data;
            REQUIRE(tracked(inputs->data, prefix));
        } else {
            REQUIRE(tracked(test_case, sizeof(*test_case)) &&
                    tracked(test_case->sections, sizeof(*test_case->sections)) &&
                    prefix <= sizeof(test_case->sections[0].code));
            data = test_case->sections[0].code;
        }
        memcpy(o.prefix, data, prefix);
    }
    return o;
}

static void reject_operation(struct attempt_adapter *a, struct attempt_handle *current,
                             struct attempt_handle *bad, const char *operation,
                             int expected, size_t prefix)
{
    struct attempt_observation before = observe_attempt(a, current, prefix);
    const char owned_header[16] = {0};
    int ret = !strcmp(operation, "feed") ? (int)attempt_feed(a, bad, owned_header, 16)
        : !strcmp(operation, "complete") ? attempt_complete(a, bad) : attempt_abort(a, bad);
    struct attempt_observation after = observe_attempt(a, current, prefix);
    REQUIRE(ret == expected);
    REQUIRE(!memcmp(before.words, after.words, sizeof(before.words)));
    REQUIRE(!memcmp(before.prefix, after.prefix, sizeof(before.prefix)));
    printf("{\"event\":\"rejection\",\"operation\":\"%s\",\"ret\":%d,"
           "\"calls_before\":%llu,\"calls_after\":%llu,\"unchanged\":true,"
           "\"prefix_bytes\":%zu}\n", operation, ret, before.words[8], after.words[8], prefix);
    fflush(stdout);
}

static void assert_failed(const struct attempt_adapter *a)
{
    REQUIRE(a->prep.phase == RVZR_PREP_FAILED && !a->prep.tc_id && !a->prep.input_id &&
            !a->prep.active_attempt && !a->fake_resources && host_tc_idle() && host_input_idle());
    REQUIRE(live_bytes == sizeof(*test_case) + sizeof(*inputs));
    REQUIRE(rvzr_prep_check_execution(&a->prep, rvzr_prep_identity(&a->prep)) != RVZR_PREP_OK);
}

static void stale_scenario(struct attempt_adapter *a, bool input)
{
    if (input) (void)prepared_tc(a);
    enum attempt_kind kind = input ? ATTEMPT_INPUT : ATTEMPT_TC;
    const char *old_path = input ? attempt_input_path : attempt_tc_path;
    const char *new_path = input ? attempt_alternate_path : attempt_tc_path;
    struct attempt_handle old = begin_file(a, old_path, kind);
    REQUIRE(drive_attempt(a, &old, old_path, old.length - 8) > 0);
    REQUIRE(!old.received && attempt_abort(a, &old) == 0);
    assert_failed(a);
    if (input) {
        struct attempt_handle denied = {0};
        REQUIRE(attempt_begin(a, &denied, kind, rvzr_prep_snapshot(&a->prep),
                              old.parent_tc, old.length) != 0);
        (void)prepared_tc(a); // Conservative input abort retires its TC too.
    }
    struct attempt_handle current = begin_file(a, new_path, kind);
    size_t prefix = input ? 4096 : 16;
    size_t received = input ? 16 + 16 + prefix : 16 + 48 + 96 + 24 + prefix;
    REQUIRE(drive_attempt(a, &current, new_path, received) > 0);
    reject_operation(a, &current, &old, "feed", -ESTALE, prefix);
    reject_operation(a, &current, &old, "complete", -ESTALE, prefix);
    reject_operation(a, &current, &old, "abort", -ESTALE, prefix);
    REQUIRE(drive_attempt(a, &current, new_path, current.length) > 0);
    compare_reset_payload(input ? attempt_expected_path : attempt_expected_tc_path);
    REQUIRE(attempt_complete(a, &current) == 0);
    if (!input) (void)prepared_input(a);
    REQUIRE(rvzr_prep_check_execution(&a->prep, rvzr_prep_identity(&a->prep)) == RVZR_PREP_OK);
}

static void identity_scenario(struct attempt_adapter *a)
{
    struct rvzr_prep_stamp old_stamp = rvzr_prep_snapshot(&a->prep);
    (void)prepared_tc(a);
    struct attempt_handle denied = {0};
    struct attempt_observation before = observe_attempt(a, &denied, 0);
    REQUIRE(attempt_begin(a, &denied, ATTEMPT_TC, old_stamp, 0, 220) == -ESTALE);
    REQUIRE(attempt_begin(a, &denied, ATTEMPT_INPUT, rvzr_prep_snapshot(&a->prep),
                          a->prep.tc_id + 1, 12320) == -ESTALE);
    struct attempt_observation after = observe_attempt(a, &denied, 0);
    REQUIRE(!memcmp(before.words, after.words, sizeof(before.words)));
    struct attempt_handle h = begin_file(a, attempt_alternate_path, ATTEMPT_INPUT), bad = h;
    bad.token.instance.high++;
    reject_operation(a, &h, &bad, "feed", -ESTALE, 0);
    bad = h; bad.kind = ATTEMPT_TC;
    reject_operation(a, &h, &bad, "feed", -EINVAL, 0);
    bad = h; bad.parent_tc++;
    reject_operation(a, &h, &bad, "feed", -ESTALE, 0);
    REQUIRE(drive_attempt(a, &h, attempt_alternate_path, h.length) > 0);
    compare_reset_payload(attempt_expected_path);
    REQUIRE(attempt_complete(a, &h) == 0);
}

static void premature_scenario(struct attempt_adapter *a)
{
    for (int input = 0; input < 2; input++) {
        if (input) (void)prepared_tc(a);
        const char *path = input ? attempt_input_path : attempt_tc_path;
        struct attempt_handle h = begin_file(a, path, input ? ATTEMPT_INPUT : ATTEMPT_TC);
        REQUIRE(drive_attempt(a, &h, path, 16) == 16);
        REQUIRE(attempt_complete(a, &h) == -EMSGSIZE);
        assert_failed(a);
    }
}

static void terminal_scenario(struct attempt_adapter *a)
{
    struct attempt_handle tc = prepared_tc(a);
    reject_operation(a, &tc, &tc, "complete", -ESTALE, 0);
    reject_operation(a, &tc, &tc, "feed", -ESTALE, 0);
    struct attempt_handle h = begin_file(a, attempt_alternate_path, ATTEMPT_INPUT);
    REQUIRE(drive_attempt(a, &h, attempt_alternate_path, h.length) > 0);
    reject_operation(a, &h, &h, "feed", -EALREADY, 4096);
    compare_reset_payload(attempt_expected_path);
    REQUIRE(a->prep.phase == RVZR_PREP_INPUT_RX && attempt_complete(a, &h) == 0);
    reject_operation(a, &h, &h, "complete", -ESTALE, 4096);
    reject_operation(a, &h, &h, "abort", -ESTALE, 4096);
    reject_operation(a, &h, &h, "feed", -ESTALE, 4096);
    REQUIRE(attempt_begin(a, &h, ATTEMPT_INPUT, rvzr_prep_snapshot(&a->prep),
                          a->prep.tc_id, h.length) == -EINVAL);
}

static void parser_error_scenario(struct attempt_adapter *a, bool input)
{
    (void)prepared_tc(a);
    (void)prepared_input(a); // Valid preparation must not be restored on replacement failure.
    size_t allocations = a->allocations, loads = a->loads;
    const char *path = input ? attempt_bad_input_path : attempt_bad_tc_path;
    struct attempt_handle h = begin_file(a, path, input ? ATTEMPT_INPUT : ATTEMPT_TC);
    REQUIRE(drive_attempt(a, &h, path, h.length) == -1);
    REQUIRE(last_parser_ret == -1 && last_finished == !input);
    assert_failed(a);
    REQUIRE(a->allocations == allocations && a->loads == loads);
    reject_operation(a, &h, &h, "complete", -ESTALE, 0);
}

static void cleanup_failure_scenario(struct attempt_adapter *a)
{
    struct attempt_handle old = prepared_tc(a);
    (void)prepared_input(a);
    a->fail_cleanup = true;
    struct attempt_handle h = {0};
    REQUIRE(attempt_begin(a, &h, ATTEMPT_TC, rvzr_prep_snapshot(&a->prep), 0, 220) == -EIO);
    REQUIRE(a->prep.phase == RVZR_PREP_UNRECOVERABLE && a->fake_resources == 3 &&
            host_tc_idle() && host_input_idle());
    struct attempt_observation before = observe_attempt(a, &h, 0);
    struct attempt_handle denied = {0};
    REQUIRE(attempt_begin(a, &denied, ATTEMPT_TC, rvzr_prep_snapshot(&a->prep), 0, 220) == -EIO);
    struct attempt_observation after = observe_attempt(a, &h, 0);
    REQUIRE(!memcmp(before.words, after.words, sizeof(before.words)));
    reject_operation(a, &h, &old, "feed", -EIO, 0);
    reject_operation(a, &h, &h, "complete", -EIO, 0);
    reject_operation(a, &h, &h, "abort", -EIO, 0);
    REQUIRE(rvzr_prep_check_execution(&a->prep, rvzr_prep_identity(&a->prep)) == RVZR_PREP_FATAL);
}

static void cycles_scenario(struct attempt_adapter *a)
{
    for (int i = 0; i < 3; i++) {
        struct attempt_handle tc = begin_file(a, attempt_tc_path, ATTEMPT_TC);
        REQUIRE(drive_attempt(a, &tc, attempt_tc_path, tc.length - 8) > 0);
        REQUIRE(attempt_abort(a, &tc) == 0);
        assert_failed(a);
        (void)prepared_tc(a);
        struct attempt_handle input = begin_file(a, attempt_input_path, ATTEMPT_INPUT);
        REQUIRE(drive_attempt(a, &input, attempt_input_path, input.length - 8) > 0);
        REQUIRE(attempt_abort(a, &input) == 0);
        assert_failed(a);
    }
    (void)prepared_tc(a);
    (void)prepared_input(a);
}

static void length_scenario(struct attempt_adapter *a)
{
    struct attempt_handle h = {0};
    const size_t invalid[] = {0, 15, ATTEMPT_MAX_BYTES + 1};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++)
        REQUIRE(attempt_begin(a, &h, ATTEMPT_TC, rvzr_prep_snapshot(&a->prep),
                              0, invalid[i]) == -EINVAL);
    REQUIRE(a->prep.phase == RVZR_PREP_EMPTY && parser_calls == 0);
    for (int input = 0; input < 2; input++) {
        const char *path = input ? attempt_input_path : attempt_tc_path;
        enum attempt_kind kind = input ? ATTEMPT_INPUT : ATTEMPT_TC;
        size_t actual = attempt_file_size(path);
        for (int shorter = 0; shorter < 2; shorter++) {
            if (input) (void)prepared_tc(a);
            h = (struct attempt_handle){0};
            REQUIRE(attempt_begin(a, &h, kind, rvzr_prep_snapshot(&a->prep),
                                  input ? a->prep.tc_id : 0, shorter ? actual - 1 : actual + 1) == 0);
            ssize_t ret = drive_attempt(a, &h, path, shorter ? h.length : actual);
            if (shorter) REQUIRE(ret > 0 && attempt_complete(a, &h) == -EMSGSIZE);
            else REQUIRE(ret == -EMSGSIZE);
            assert_failed(a);
        }
        if (input) (void)prepared_tc(a);
        h = begin_file(a, path, kind);
        size_t before = parser_calls;
        const char short_header[8] = {0};
        REQUIRE(attempt_feed(a, &h, short_header, sizeof(short_header)) == -EINVAL);
        REQUIRE(parser_calls == before);
        assert_failed(a);
    }
}

static void phase_scenario(struct attempt_adapter *a)
{
    for (int stage = 1; stage <= 3; stage++) {
        struct attempt_handle h = begin_file(a, attempt_tc_path, ATTEMPT_TC);
        REQUIRE(drive_attempt(a, &h, attempt_tc_path, 16) == 16);
        for (int i = 0; i < stage; i++) REQUIRE(rvzr_prep_advance_tc(&a->prep, h.token) == RVZR_PREP_OK);
        REQUIRE(rvzr_prep_check_attempt(&a->prep, h.token) == RVZR_PREP_OK);
        reject_operation(a, &h, &h, "feed", -EINVAL, 0);
        reject_operation(a, &h, &h, "complete", -EINVAL, 0);
        REQUIRE(attempt_abort(a, &h) == 0);
        assert_failed(a);
    }
}

static int attempt_scenario(int argc, char **argv)
{
    if (argc != 10) fatal("usage: harness attempt SCENARIO TC INPUT ALT BAD_TC BAD_INPUT INPUT_BYTES TC_BYTES");
    const char *scenario = argv[2];
    attempt_tc_path = argv[3]; attempt_input_path = argv[4]; attempt_alternate_path = argv[5];
    attempt_bad_tc_path = argv[6]; attempt_bad_input_path = argv[7]; attempt_expected_path = argv[8];
    attempt_expected_tc_path = argv[9];
    if (init_test_case_parser() || init_input_parser()) fatal("parser initialization failed");
    struct attempt_adapter a;
    attempt_init(&a);
    if (!strcmp(scenario, "valid")) { (void)prepared_tc(&a); (void)prepared_input(&a); }
    else if (!strcmp(scenario, "stale-input")) stale_scenario(&a, true);
    else if (!strcmp(scenario, "stale-tc")) stale_scenario(&a, false);
    else if (!strcmp(scenario, "identity")) identity_scenario(&a);
    else if (!strcmp(scenario, "premature")) premature_scenario(&a);
    else if (!strcmp(scenario, "terminal")) terminal_scenario(&a);
    else if (!strcmp(scenario, "parser-error-tc")) parser_error_scenario(&a, false);
    else if (!strcmp(scenario, "parser-error-input")) parser_error_scenario(&a, true);
    else if (!strcmp(scenario, "cleanup-failure")) cleanup_failure_scenario(&a);
    else if (!strcmp(scenario, "cycles")) cycles_scenario(&a);
    else if (!strcmp(scenario, "lengths")) length_scenario(&a);
    else if (!strcmp(scenario, "phase")) phase_scenario(&a);
    else fatal("unknown bounded attempt scenario");
    printf("{\"event\":\"attempt_result\",\"state\":\"%s\",\"parser_calls\":%zu,"
           "\"tc_resets\":%zu,\"input_resets\":%zu,\"cleanup_calls\":%zu,"
           "\"fake_resources\":%u,\"allocations\":%zu,\"loads\":%zu}\n",
           attempt_phase(&a), parser_calls, a.tc_resets, a.input_resets, a.cleanup_calls,
           a.fake_resources, a.allocations, a.loads);
    REQUIRE(!trace_calls && !sandbox_calls && !code_calls); // No legacy preparation/execution callback.
    free_input_parser(); free_test_case_parser();
    printf("{\"event\":\"teardown\",\"live_bytes\":%zu}\n", live_bytes);
    return live_bytes ? 66 : 0;
}
#undef REQUIRE
