/* Compile real parsers in separate TUs; direct-parser baseline only.
 * Only owned host buffers are used; no kernel, PMU or test-case code executes.
 */
#include "compat.h"
#include "test_case_parser.h"
#include "input_parser.h"
#include "shortcuts.h"

_Static_assert(sizeof(void *) == 8 && sizeof(uint64_t) == 8, "64-bit host required");

#define MAX_FILE (128 * 1024)
#define MAX_LIVE (2 * 1024 * 1024)
#define MAX_BLOCKS 128
#define MAX_CALLS 4096

static struct { void *pointer; size_t size; } blocks[MAX_BLOCKS];
static size_t live_bytes, total_attempts, calls;
static bool use_inputs, last_finished;
static ssize_t last_parser_ret;

uint64_t host_tc_cursor(void);
uint64_t host_input_cursor(void);

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

/* No sysfs callbacks, callback extraction, linker wrapping or failure injection. */

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
    ssize_t ret = use_inputs ? parse_input_buffer(buffer, count, &finished)
                            : parse_test_case_buffer(buffer, count, &finished);
    last_parser_ret = ret;
    last_finished = finished;
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

int main(int argc, char **argv)
{
    if (argc != 6 || (strcmp(argv[1], "rcbf") && strcmp(argv[1], "rdbf")) ||
        strcmp(argv[2], "direct"))
        fatal("usage: harness rcbf|rdbf direct FIXTURE PREFIX_BYTES STEP_BYTES");
    use_inputs = !strcmp(argv[1], "rdbf");
    char data[MAX_FILE];
    FILE *file = fopen(argv[3], "rb");
    if (!file) fatal("cannot open owned fixture");
    size_t length = fread(data, 1, sizeof(data), file);
    if (ferror(file) || fgetc(file) != EOF) fatal("fixture bound exceeded/read failure");
    fclose(file);
    size_t count = bounded_number(argv[4], length);
    size_t step = bounded_number(argv[5], PAGE_SIZE);
    if (count < 16 || step < 16) fatal("baseline requires a complete 16-byte header");
    int err = init_test_case_parser();
    if (!err) err = init_input_parser();
    if (err) fatal("unexpected parser initialization failure");
    emit("init", 0, 0);
    size_t offset = 0;
    int status = 0;
    while (count) {
        size_t requested = count < step ? count : step;
        ssize_t ret = feed(data + offset, requested);
        if (ret <= 0 || (size_t)ret > requested) { status = 65; break; }
        offset += (size_t)ret;
        count -= (size_t)ret;
    }
    free_input_parser();
    free_test_case_parser();
    printf("{\"event\":\"teardown\",\"live_bytes\":%zu}\n", live_bytes);
    if (live_bytes) status = 66;
    for (size_t i = 0; i < MAX_BLOCKS; i++)
        if (blocks[i].pointer) host_free(blocks[i].pointer);
    return status;
}
