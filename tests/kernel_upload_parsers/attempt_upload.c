/* Host-only boundary logic using the real state machine and parsers/resets.
 * Single-threaded, fixed limits; no sysfs, file operations or native resources.
 */
#include "attempt_upload.h"
#include "test_case_parser.h"
#include "input_parser.h"

bool host_tc_idle(void);
bool host_input_idle(void);
bool host_parser_roots_only(void);

static int state_error(enum rvzr_prep_result result)
{
    if (result == RVZR_PREP_OK) return 0;
    if (result == RVZR_PREP_STALE) return -ESTALE;
    if (result == RVZR_PREP_FATAL || result == RVZR_PREP_EXHAUSTED) return -EIO;
    return -EINVAL;
}

void attempt_init(struct attempt_adapter *a)
{
    /* Constructor only: scenarios call it once, never to escape fatal state. */
    memset(a, 0, sizeof(*a));
    if (rvzr_prep_init(&a->prep, (struct rvzr_prep_instance){17, 29}) != RVZR_PREP_OK)
        abort();
}

static int reset_input(struct attempt_adapter *a)
{
    a->input_resets++;
    int ret = reset_input_parser();
    return ret ? ret : host_input_idle() ? 0 : -EIO;
}

static int cleanup(struct attempt_adapter *a)
{
    a->cleanup_calls++;
    /* Explicit fake-resource release; a failure leaves those bits quarantined. */
    if (!a->fail_cleanup) a->fake_resources = 0;
    int input_ret = reset_input(a);
    a->tc_resets++;
    int tc_ret = reset_test_case_parser();
    bool safe = !a->fail_cleanup && !a->fake_resources && !input_ret && !tc_ret &&
        host_tc_idle() && host_parser_roots_only();
    int ret = state_error(rvzr_prep_cleanup_done(&a->prep, rvzr_prep_snapshot(&a->prep), safe));
    return ret ? ret : safe ? 0 : -EIO;
}

static int authorize(const struct attempt_adapter *a, const struct attempt_handle *h,
                     bool receiving)
{
    int ret = state_error(rvzr_prep_check_attempt(&a->prep, h->token));
    if (ret) return ret;
    if (h->kind == ATTEMPT_INPUT) {
        if (a->prep.phase != RVZR_PREP_INPUT_RX) return -EINVAL;
        if (h->parent_tc != a->prep.tc_id) return -ESTALE;
    } else if (h->kind == ATTEMPT_TC) {
        if (receiving && a->prep.phase != RVZR_PREP_TC_RX) return -EINVAL;
        if (!receiving && a->prep.phase != RVZR_PREP_TC_RX &&
            a->prep.phase != RVZR_PREP_TC_VALIDATE && a->prep.phase != RVZR_PREP_TC_ALLOCATE &&
            a->prep.phase != RVZR_PREP_TC_LOAD) return -EINVAL;
    } else {
        return -EINVAL;
    }
    return 0;
}

static int fail_attempt(struct attempt_adapter *a, const struct attempt_handle *h, int error)
{
    int ret = state_error(rvzr_prep_fail(&a->prep, h->token));
    if (ret) return ret;
    ret = cleanup(a);
    return ret ? ret : error;
}

int attempt_begin(struct attempt_adapter *a, struct attempt_handle *h,
                  enum attempt_kind kind, struct rvzr_prep_stamp expected,
                  rvzr_prep_u64 parent_tc, size_t length)
{
    if (h->token.id || (kind != ATTEMPT_TC && kind != ATTEMPT_INPUT) ||
        length < 16 || length > ATTEMPT_MAX_BYTES) return -EINVAL;
    struct rvzr_prep_attempt token;
    enum rvzr_prep_result result = kind == ATTEMPT_TC
        ? rvzr_prep_begin_tc(&a->prep, expected, &token)
        : rvzr_prep_begin_input(&a->prep, expected, parent_tc, &token);
    int ret = state_error(result);
    if (ret) return ret;
    *h = (struct attempt_handle){.token = token, .kind = kind, .parent_tc = parent_tc,
                                 .length = length};
    if (kind == ATTEMPT_TC) return cleanup(a);
    ret = reset_input(a);
    return ret ? fail_attempt(a, h, ret) : 0;
}

ssize_t attempt_feed(struct attempt_adapter *a, struct attempt_handle *h,
                     const char *bytes, size_t count)
{
    int ret = authorize(a, h, true);
    if (ret) return ret; /* Absolutely no reset or parser call on stale/wrong-kind input. */
    if (h->received) return -EALREADY;
    if (!bytes || !count || count > PAGE_SIZE || h->position > h->length ||
        count > h->length - h->position || (!h->position && count < 16))
        return fail_attempt(a, h, -EINVAL);
    /* Existing parsers require a whole header. Offer only its 16 bytes on call one. */
    size_t offered = h->position ? count : 16;
    bool finished = false;
    ssize_t consumed = h->kind == ATTEMPT_TC
        ? parse_test_case_buffer(bytes, offered, &finished)
        : parse_input_buffer(bytes, offered, &finished);
    if (consumed < 0) return fail_attempt(a, h, (int)consumed);
    if (!consumed || (size_t)consumed > offered) return fail_attempt(a, h, -EIO);
    h->position += (size_t)consumed;
    if (finished && h->position != h->length) return fail_attempt(a, h, -EMSGSIZE);
    h->received = finished;
    return consumed;
}

int attempt_complete(struct attempt_adapter *a, struct attempt_handle *h)
{
    int ret = authorize(a, h, true);
    if (ret) return ret;
    if (!h->received || h->position != h->length) return fail_attempt(a, h, -EMSGSIZE);
    if (h->kind == ATTEMPT_INPUT)
        return state_error(rvzr_prep_commit_input(&a->prep, h->token));
    /* The parser's successful final call already performed semantic validation.
     * Native CPU compatibility, allocation and code loading are NOT exercised.
     */
    ret = state_error(rvzr_prep_advance_tc(&a->prep, h->token));
    if (ret) return ret;
    ret = state_error(rvzr_prep_advance_tc(&a->prep, h->token));
    if (ret) return ret;
    a->allocations++;
    a->fake_resources |= 1;
    ret = state_error(rvzr_prep_advance_tc(&a->prep, h->token));
    if (ret) return ret;
    a->loads++;
    a->fake_resources |= 2;
    return state_error(rvzr_prep_commit_tc(&a->prep, h->token));
}

int attempt_abort(struct attempt_adapter *a, const struct attempt_handle *h)
{
    int ret = authorize(a, h, false);
    if (ret) return ret;
    ret = state_error(rvzr_prep_abort(&a->prep, h->token));
    return ret ? ret : cleanup(a);
}
