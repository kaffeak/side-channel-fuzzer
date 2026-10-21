/* Compile real parsers and an extracted production callback in separate TUs.
 * Only owned host buffers are used; no kernel, PMU or test-case code executes.
 */
#include "compat.h"
#include "test_case_parser.h"
#include "input_parser.h"
#include "sandbox_manager.h"
#include "code_loader.h"
#include "shortcuts.h"

_Static_assert(sizeof(void *) == 8 && sizeof(uint64_t) == 8, "64-bit host required");

#define MAX_FILE (128 * 1024)
#define MAX_LIVE (2 * 1024 * 1024)
#define MAX_BLOCKS 128
#define MAX_CALLS 4096

static struct { void *pointer; size_t size; } blocks[MAX_BLOCKS];
static size_t live_bytes, total_attempts, calls;
static bool use_inputs, use_store, last_finished;
static ssize_t last_parser_ret;
static size_t sandbox_calls, code_calls, parser_calls;
static size_t upload_id;
static bool ready_before_call, ready_at_parser_entry;

/* Storage for the actual callback's globals, with the production initial values. */
bool tc_ready = false;
bool inputs_ready = false;
bool unfinished_call = false;
int next_measurement_id = -1;
measurement_t *measurements;
static measurement_t owned_measurements[64];
static size_t trace_calls;

uint64_t host_tc_cursor(void);
uint64_t host_input_cursor(void);
ssize_t host_test_case_store(const char *buf, size_t count);
ssize_t host_trace_show(char *buf);
ssize_t __real_parse_test_case_buffer(const char *buf, size_t count, bool *finished);

/* GNU ld wrapping observes the real parser without changing its return or flag. */
ssize_t __wrap_parse_test_case_buffer(const char *buf, size_t count, bool *finished)
{
    parser_calls++;
    ready_at_parser_entry = tc_ready;
    last_parser_ret = __real_parse_test_case_buffer(buf, count, finished);
    last_finished = *finished;
    return last_parser_ret;
}

/* Counted success stubs only: no sandbox allocation or test-case code loading. */
int allocate_sandbox(void)
{
    sandbox_calls++;
    return 0;
}

int load_sandbox_code(void)
{
    code_calls++;
    return 0;
}

static void fatal(const char *message)
{
    fprintf(stderr, "harness: %s\n", message);
    exit(64);
}

void *host_allocate(size_t size, bool zero)
{
    total_attempts++;
    if (!size || size > MAX_LIVE || live_bytes > MAX_LIVE - size)
        fatal("allocation bound exceeded (not an injected parser failure)");
    for (size_t i = 0; i < MAX_BLOCKS; i++) {
        if (blocks[i].pointer)
            continue;
        void *pointer = zero ? calloc(1, size) : malloc(size);
        if (!pointer)
            fatal("unexpected host allocation failure");
        blocks[i].pointer = pointer;
        blocks[i].size = size;
        live_bytes += size;
        return pointer;
    }
    fatal("allocation registry bound exceeded");
    return NULL;
}

void host_free(void *pointer)
{
    if (!pointer)
        return;
    for (size_t i = 0; i < MAX_BLOCKS; i++) {
        if (blocks[i].pointer != pointer)
            continue;
        live_bytes -= blocks[i].size;
        blocks[i].pointer = NULL;
        free(pointer);
        return;
    }
    fatal("free of untracked/freed pointer");
}

static size_t allocation_size(void *pointer)
{
    for (size_t i = 0; i < MAX_BLOCKS; i++)
        if (pointer && blocks[i].pointer == pointer)
            return blocks[i].size;
    return 0;
}

static bool tracked_range(void *base, size_t offset, size_t length)
{
    size_t size = allocation_size(base);
    return size > 0 && offset <= size && length <= size - offset;
}

static bool tracked(void *pointer, size_t minimum)
{
    return tracked_range(pointer, 0, minimum);
}

static uint64_t hash_bytes(uint64_t hash, const void *pointer, size_t size)
{
    const unsigned char *bytes = pointer;
    for (size_t i = 0; i < size; i++) {
        hash ^= bytes[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static void emit(const char *event, size_t requested, ssize_t ret)
{
    bool completed = use_inputs ? input_parsing_completed() : tc_parsing_completed();
    uint64_t cursor_ = use_inputs ? host_input_cursor() : host_tc_cursor();
    printf("{\"event\":\"%s\",\"requested\":%zu,\"ret\":%zd,"
           "\"finished\":%s,\"not_receiving\":%s,\"receiving\":%s,\"cursor\":%llu,"
           "\"n_actors\":%zu,\"n_inputs\":%zu,\"allocation_attempts\":%zu,"
           "\"live_bytes\":%zu,\"consumed\":",
           event, requested, ret, last_finished ? "true" : "false",
           completed ? "true" : "false", completed ? "false" : "true", cursor_,
           n_actors, n_inputs, total_attempts, live_bytes);
    if (ret >= 0) printf("%zd", ret); else printf("null");
    printf(",\"parser_ret\":");
    if (parser_calls) printf("%zd", last_parser_ret); else printf("null");
    printf(",\"parser_calls\":%zu,\"callback_ret\":", parser_calls);
    if (use_store && !strcmp(event, "feed")) printf("%zd", ret); else printf("null");
    printf(",\"tc_ready\":%s,\"sandbox_calls\":%zu,\"code_calls\":%zu,"
           "\"next_measurement_id\":%d,\"upload_id\":%zu,\"ready_before_call\":%s,"
           "\"ready_at_parser_entry\":",
           tc_ready ? "true" : "false", sandbox_calls, code_calls, next_measurement_id,
           upload_id, ready_before_call ? "true" : "false");
    if (use_store && parser_calls)
        printf("%s", ready_at_parser_entry ? "true" : "false");
    else
        printf("null");
    printf(",\"metadata_allocation_bytes\":");
    if (!use_inputs && tracked(test_case, sizeof(*test_case)))
        printf("%zu", allocation_size(test_case->metadata));
    else
        printf("null");
    printf(",\"hash\":");
    uint64_t hash = 14695981039346656037ULL;
    bool have_hash = false;
    if (last_parser_ret >= 0 && last_finished && use_inputs && tracked(inputs, sizeof(*inputs)) &&
        tracked(inputs->data, inputs->data_size) && inputs->data_size <= MAX_FILE) {
        hash = hash_bytes(hash, inputs->data, inputs->data_size);
        have_hash = true;
    } else if (last_parser_ret >= 0 && last_finished && !use_inputs &&
               tracked(test_case, sizeof(*test_case)) && n_actors > 0 && n_actors <= 4 &&
               tracked(test_case->metadata, n_actors * sizeof(*test_case->metadata)) &&
               tracked(test_case->sections, n_actors * sizeof(*test_case->sections))) {
        have_hash = true;
        for (size_t i = 0; i < n_actors; i++) {
            size_t size = test_case->metadata[i].size;
            size_t offset = i * sizeof(*test_case->sections) + offsetof(tc_section_t, code);
            /* code is inline in the sections allocation, not a separately allocated pointer. */
            if (size > sizeof(test_case->sections[i].code) ||
                !tracked_range(test_case->sections, offset, size)) {
                have_hash = false;
                break;
            }
            hash = hash_bytes(hash, (unsigned char *)test_case->sections + offset, size);
        }
    }
    if (have_hash) printf("\"%016llx\"", hash); else printf("null");
    puts("}");
    fflush(stdout); /* Preserve preceding observations if the next call trips ASan. */
}

static ssize_t feed(const char *source, size_t count)
{
    if (++calls > MAX_CALLS)
        fatal("parser call bound exceeded");
    /* kernfs also supplies a terminating NUL, not a padded 16-byte header. */
    char *buffer = malloc(count + 1);
    if (!buffer) fatal("callback buffer allocation failed");
    memcpy(buffer, source, count);
    buffer[count] = '\0';
    bool finished = false;
    ssize_t ret;
    if (use_store) {
        size_t previous_calls = parser_calls;
        ready_before_call = tc_ready;
        ret = host_test_case_store(buffer, count);
        if (parser_calls != previous_calls + 1)
            fatal("callback did not call the observed production parser exactly once");
    } else if (use_inputs) {
        parser_calls++;
        ret = parse_input_buffer(buffer, count, &finished);
        last_parser_ret = ret;
        last_finished = finished;
    } else {
        ret = parse_test_case_buffer(buffer, count, &finished);
    }
    emit("feed", count, ret);
    free(buffer);
    return ret;
}

static size_t bounded_number(const char *text, size_t maximum)
{
    if (!*text) fatal("empty number");
    for (const char *p = text; *p; p++)
        if (*p < '0' || *p > '9') fatal("expected unsigned decimal number");
    errno = 0;
    char *end;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno || *end || !value || value > maximum) fatal("number outside bounds");
    return (size_t)value;
}

static size_t read_fixture(const char *path, char *data)
{
    FILE *file = fopen(path, "rb");
    if (!file) fatal("cannot open owned fixture");
    size_t length = fread(data, 1, MAX_FILE, file);
    if (ferror(file) || fgetc(file) != EOF) fatal("fixture bound exceeded/read failure");
    fclose(file);
    return length;
}

static void seed_measurements(void)
{
    if (n_inputs > 64) fatal("measurement fixture bound exceeded");
    for (size_t i = 0; i < n_inputs; i++) {
        /* Twenty-digit values force pagination; small fixtures have readable results. */
        uint64_t value = n_inputs == 64 ? ~0ULL - i : i + 1;
        owned_measurements[i].htrace[0] = value;
        for (size_t j = 0; j < NUM_PFC; j++)
            owned_measurements[i].pfc_reading[j] = value;
    }
}

/* Success stub only. Admission must be enforced by the real trace_show(), not here. */
int trace_test_case(void)
{
    trace_calls++;
    seed_measurements();
    return 0;
}

static void observe_trace(size_t page)
{
    char buffer[PAGE_SIZE], before[PAGE_SIZE];
    memset(buffer, 0xA5, sizeof(buffer));
    memcpy(before, buffer, sizeof(buffer));
    int previous_id = next_measurement_id;
    bool previous_unfinished = unfinished_call;
    ssize_t ret = host_trace_show(buffer);
    if (ret >= (ssize_t)sizeof(buffer)) fatal("trace output exceeds owned buffer");
    printf("{\"event\":\"trace\",\"page\":%zu,\"ret\":%zd,\"trace_calls\":%zu,"
           "\"tc_ready\":%s,\"inputs_ready\":%s,\"unfinished_before\":%s,"
           "\"unfinished_after\":%s,\"next_before\":%d,\"next_after\":%d,"
           "\"buffer_unchanged\":%s,\"tc_completed\":%s,\"inputs_completed\":%s,"
           "\"output_hex\":\"",
           page, ret, trace_calls, tc_ready ? "true" : "false",
           inputs_ready ? "true" : "false", previous_unfinished ? "true" : "false",
           unfinished_call ? "true" : "false", previous_id, next_measurement_id,
           memcmp(buffer, before, sizeof(buffer)) == 0 ? "true" : "false",
           tc_parsing_completed() ? "true" : "false",
           input_parsing_completed() ? "true" : "false");
    /* Negative returns expose no buffer contents, even if a defective callback wrote them. */
    for (ssize_t i = 0; i < ret; i++) printf("%02x", (unsigned char)buffer[i]);
    puts("\"}");
    fflush(stdout);
}

static bool boolean_argument(const char *text)
{
    if (strcmp(text, "0") && strcmp(text, "1")) fatal("expected 0 or 1");
    return !strcmp(text, "1");
}

static int trace_scenario(int argc, char **argv)
{
    if (argc != 6 || (strcmp(argv[5], "execute") && strcmp(argv[5], "pending") &&
                      strcmp(argv[5], "paginate")))
        fatal("usage: harness trace TC_READY INPUTS_READY UNFINISHED execute|pending|paginate");
    bool selected_tc = boolean_argument(argv[2]);
    bool selected_inputs = boolean_argument(argv[3]);
    unfinished_call = boolean_argument(argv[4]);
    bool paginate = !strcmp(argv[5], "paginate");
    if (init_test_case_parser() || init_input_parser()) fatal("parser initialization failed");
    tc_ready = paginate ? true : selected_tc;
    inputs_ready = paginate ? true : selected_inputs;
    n_inputs = paginate ? 64 : 2;
    measurements = owned_measurements;
    seed_measurements();
    next_measurement_id = !strcmp(argv[5], "pending") ? 1 : -1;
    observe_trace(0);
    if (paginate) {
        /* Explicit synthetic invalidation between real callback calls, not an upload model. */
        tc_ready = selected_tc;
        inputs_ready = selected_inputs;
        observe_trace(1);
    }
    free_input_parser();
    free_test_case_parser();
    printf("{\"event\":\"teardown\",\"live_bytes\":%zu}\n", live_bytes);
    return live_bytes ? 66 : 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "trace")) return trace_scenario(argc, argv);
    if ((argc != 6 && argc != 7) || (strcmp(argv[1], "rcbf") && strcmp(argv[1], "rdbf")) ||
        (strcmp(argv[2], "direct") && strcmp(argv[2], "store")))
        fatal("usage: harness rcbf|rdbf direct|store FIXTURE PREFIX_BYTES STEP_BYTES [REPLACEMENT]");
    use_inputs = !strcmp(argv[1], "rdbf");
    use_store = !strcmp(argv[2], "store");
    if (use_inputs && use_store) fatal("only the RCBF test_case_store callback is supported");
    char data[MAX_FILE];
    size_t length = read_fixture(argv[3], data);
    size_t count = bounded_number(argv[4], length);
    size_t step = bounded_number(argv[5], PAGE_SIZE);
    if (count < 16 || step < 16) fatal("baseline requires a complete 16-byte header");
    if (argc == 7 && (!use_store || count != length))
        fatal("replacement requires store mode and a complete initial upload");
    int err = init_test_case_parser();
    if (!err) err = init_input_parser();
    if (err) fatal("unexpected parser initialization failure");
    emit("init", 0, 0);
    int status = 0;
    for (upload_id = 0; upload_id < (argc == 7 ? 2U : 1U); upload_id++) {
        if (upload_id == 1) {
            count = read_fixture(argv[6], data);
            if (count < 16) fatal("replacement requires a complete 16-byte header");
        }
        size_t offset = 0;
        while (count) {
            size_t requested = count < step ? count : step;
            ssize_t ret = feed(data + offset, requested);
            if (ret <= 0 || (size_t)ret > requested) { status = 65; break; }
            offset += (size_t)ret;
            count -= (size_t)ret;
        }
        if (status) break;
    }
    free_input_parser();
    free_test_case_parser();
    printf("{\"event\":\"teardown\",\"live_bytes\":%zu}\n", live_bytes);
    if (live_bytes) status = 66;
    for (size_t i = 0; i < MAX_BLOCKS; i++)
        if (blocks[i].pointer) host_free(blocks[i].pointer);
    return status;
}
