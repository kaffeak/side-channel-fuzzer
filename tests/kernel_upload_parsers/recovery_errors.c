/* Included by the bounded production-function extractor in unit_pte_recovery_errors.py.
 * Return-value/order stubs only. No PTEs, page walks, IRQ changes or generated code.
 */
#include "main.h"
#include "code_loader.h"
#include "data_loader.h"
#include "fault_handler.h"
#include "input_parser.h"
#include "measurement.h"
#include "sandbox_manager.h"
#include "special_registers.h"
#include "test_case_parser.h"
#include "shortcuts.h"

static actor_data_t owned_data;
static util_t owned_util;
static sandbox_t owned_sandbox = {.data = &owned_data, .util = &owned_util};
static measurement_t owned_measurement;
static test_case_t owned_test_case;
sandbox_t *sandbox = &owned_sandbox;
measurement_t *measurements = &owned_measurement;
test_case_t *test_case = &owned_test_case;
size_t n_inputs = 1;
size_t n_actors = 1;
uint8_t *loaded_test_case_entry;
bool tc_ready = true, inputs_ready = true, unfinished_call;
bool quick_and_dirty_mode = true, dbg_gpr_mode;
char pre_run_flush;
long uarch_reset_rounds;
int next_measurement_id = -1;
static int restore_result, setup_result;
static char events[64];
static size_t event_count;

ssize_t host_trace_entry(char *buf);

static void event(char value)
{
    if (event_count >= sizeof(events) - 1) abort();
    events[event_count++] = value;
}

int restore_orig_host_permissions(void) { event('H'); return restore_result; }
void restore_faulty_page_permissions(void) { event('F'); }
void restore_special_registers(void) { event('S'); }
int set_sandbox_page_tables(void) { event('B'); return setup_result; }
int set_special_registers(void) { event('C'); return 0; }
int load_sandbox_data(int input_id) { if (input_id) abort(); event('D'); return 0; }
void set_faulty_page_permissions(void) { event('A'); }
void set_inner_fault_handlers(void) { event('I'); }
void unset_inner_fault_handlers(void) { event('U'); }
bool input_parsing_completed(void) { return true; }
bool tc_parsing_completed(void) { return true; }
int alloc_measurements(void) { event('M'); return 0; }

/* Deliberately replace CPU setup/teardown and the assembly wrapper, not recovery logic. */
static int pre_run(unsigned long *flags) { *flags = 0; event('P'); return 0; }
static inline void post_run(unsigned long *flags) { if (*flags) abort(); event('Q'); }
int run_experiment_outer(void) { event('O'); return run_experiment(); }

/* Ordinary host C stub reached through the production loop's function pointer.
 * This is not a generated test case and collects no hardware observations.
 */
static int owned_entry(char *base)
{
    if (base != (char *)owned_data.main_area) abort();
    event('E');
    owned_util.vars.latest_measurement.status.measurement_state = STATUS_ENDED;
    owned_util.vars.latest_measurement.htrace[0] = 17;
    for (size_t i = 0; i < NUM_PFC; i++)
        owned_util.vars.latest_measurement.pfc_reading[i] = i;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 4) return 64;
    /* Fixed choices, not an arbitrary fault-injection interface. */
    if (!strcmp(argv[2], "ok")) restore_result = 0;
    else if (!strcmp(argv[2], "io")) restore_result = -EIO;
    else if (!strcmp(argv[2], "stale")) restore_result = -ESTALE;
    else return 64;
    if (!strcmp(argv[3], "setup-error")) setup_result = -EINVAL;
    else if (strcmp(argv[3], "normal")) return 64;
    loaded_test_case_entry = (uint8_t *)owned_entry;
    char buffer[PAGE_SIZE], before[PAGE_SIZE];
    memset(buffer, 0xA5, sizeof(buffer));
    memcpy(before, buffer, sizeof(buffer));
    ssize_t ret, repeat = 0;
    if (!strcmp(argv[1], "wrapper")) ret = restore_orig_sandbox_page_tables();
    else if (!strcmp(argv[1], "recover")) ret = recover_orig_state();
    else if (!strcmp(argv[1], "run")) ret = run_experiment();
    else if (!strcmp(argv[1], "trace")) ret = host_trace_entry(buffer);
    else return 64;
    bool unchanged = !memcmp(buffer, before, sizeof(buffer));
    if (ret > (ssize_t)sizeof(buffer)) abort();
    size_t first_events = event_count;
    if (!strcmp(argv[1], "trace") && ret < 0) {
        /* Changing a stub result must not clear the real callback's terminal condition. */
        restore_result = 0;
        repeat = host_trace_entry(buffer);
    }
    printf("{\"ret\":%zd,\"repeat\":%zd,\"events\":\"%s\",\"first_events\":%zu,"
           "\"buffer_unchanged\":%s,\"repeat_buffer_unchanged\":%s,"
           "\"unfinished\":%s,\"tc_ready\":%s,\"inputs_ready\":%s,\"next\":%d,"
           "\"output_hex\":\"",
           ret, repeat, events, first_events, unchanged ? "true" : "false",
           !memcmp(buffer, before, sizeof(buffer)) ? "true" : "false",
           unfinished_call ? "true" : "false", tc_ready ? "true" : "false",
           inputs_ready ? "true" : "false", next_measurement_id);
    if (!strcmp(argv[1], "trace"))
        for (ssize_t i = 0; i < ret; i++) printf("%02x", (unsigned char)buffer[i]);
    puts("\"}");
    return 0;
}
