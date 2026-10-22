/* Exercises the production shim with synthetic ES messages. No live client,
 * entitlement, host changes or signing. Also compiles against the base shim. */
#include <EndpointSecurity/EndpointSecurity.h>
#include <dispatch/dispatch.h>
#include <Block.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

static es_return_t delete_result = ES_RETURN_SUCCESS;
static unsigned freed = 0;
static void tracked_free(void *p) { ++freed; free(p); }
static es_return_t fake_delete(es_client_t *client) { (void)client; return delete_result; }
static void (^late)(void);
static void (^pending)(void);
static unsigned sync_call;
static es_return_t fake_sync(es_client_t *client, void (^block)(void)) {
    (void)client;
    if (sync_call++ == 0) late = Block_copy(block);
    else if (sync_call == 2) { late(); Block_release(late); late = NULL; pending = Block_copy(block); }
    else block();
    return ES_RETURN_SUCCESS;
}
#define es_delete_client fake_delete
#define es_sync_client fake_sync
#define free tracked_free
#include "obs_shim.c"
#undef free

static ukai_obs_client_t *new_fake(void) {
    ukai_obs_client_t *self = calloc(1, sizeof(*self));
    self->ring = calloc(UKAI_OBS_RING_CAPACITY, sizeof(ukai_obs_event));
#ifndef UKAI_OBS_HELPERS_MAX
    self->synced = dispatch_semaphore_create(0);
#endif
    return self;
}
static es_file_t file(const char *path) {
    es_file_t result = {0};
    result.path.data = path; result.path.length = strlen(path);
    return result;
}
static es_string_token_t name(const char *s) {
    es_string_token_t n = { .data = s, .length = strlen(s) }; return n;
}
static void equals(const uint8_t *actual, uint16_t length, const char *expected) {
    assert(length == strlen(expected)); assert(memcmp(actual, expected, length) == 0);
}
int main(int argc, char **argv) {
    assert(argc == 2);
    ukai_obs_client_t *self = new_fake();
    es_file_t src = file("/w/source"), dir = file("/w/dest"), exe = file("/bin/tool");
    es_process_t process = {0};
    process.audit_token.val[5] = 123; process.audit_token.val[7] = 4;
    process.executable = &exe;
    es_message_t m = {0};
    m.version = 4; m.process = &process;
    ukai_obs_event out;
    if (!strcmp(argv[1], "close")) {
        m.event_type = ES_EVENT_TYPE_NOTIFY_CLOSE; m.event.close.target = &src;
        m.event.close.modified = false; handle(NULL, &m, self);
        assert(ukai_obs_poll(self, &out));
        assert(out.seq == 0 && out.global_seq == 0);
#ifdef UKAI_OBS_HELPERS_MAX
        assert(out.ignored); assert(out.event_type == ES_EVENT_TYPE_NOTIFY_CLOSE);
#endif
        m.seq_num = 1; m.global_seq_num = 1; m.event.close.modified = true;
        handle(NULL, &m, self); assert(ukai_obs_poll(self, &out));
        assert(out.seq == 1 && out.modified == 1);
    } else if (!strcmp(argv[1], "types")) {
        m.event_type = ES_EVENT_TYPE_NOTIFY_SETMODE; m.event.setmode.target = &src;
        handle(NULL, &m, self); assert(ukai_obs_poll(self, &out));
        int mode = out.type;
        m.event_type = ES_EVENT_TYPE_NOTIFY_TRUNCATE; m.event.truncate.target = &src;
        handle(NULL, &m, self); assert(ukai_obs_poll(self, &out));
        assert(mode != out.type);
#ifdef UKAI_OBS_HELPERS_MAX
        assert(out.event_type == ES_EVENT_TYPE_NOTIFY_TRUNCATE);
#endif
    } else if (!strcmp(argv[1], "paths")) {
        m.event_type = ES_EVENT_TYPE_NOTIFY_CREATE;
        m.event.create.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
        m.event.create.destination.new_path.dir = &dir;
        m.event.create.destination.new_path.filename = name("new");
        handle(NULL, &m, self); assert(ukai_obs_poll(self, &out));
        equals(out.path, out.path_len, "/w/dest/new");
        assert(out.type == 11); // denied creation, never success
        m.event_type = ES_EVENT_TYPE_NOTIFY_RENAME;
        m.event.rename.source = &src;
        m.event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
        m.event.rename.destination.new_path.dir = &dir;
        m.event.rename.destination.new_path.filename = name("moved");
        handle(NULL, &m, self); assert(ukai_obs_poll(self, &out));
        equals(out.path, out.path_len, "/w/source");
#ifdef UKAI_OBS_HELPERS_MAX
        equals(out.path2, out.path2_len, "/w/dest/moved");
#endif
        m.event_type = ES_EVENT_TYPE_NOTIFY_LINK;
        m.event.link.source = &src; m.event.link.target_dir = &dir;
        m.event.link.target_filename = name("link");
        handle(NULL, &m, self); assert(ukai_obs_poll(self, &out));
        equals(out.path, out.path_len, "/w/source");
#ifdef UKAI_OBS_HELPERS_MAX
        equals(out.path2, out.path2_len, "/w/dest/link");
#endif
    } else if (!strcmp(argv[1], "unknown")) {
        m.event_type = ES_EVENT_TYPE_NOTIFY_TRUNCATE; m.event.truncate.target = NULL;
        handle(NULL, &m, self); assert(ukai_obs_gap(self));
        assert(ukai_obs_poll(self, &out)); assert(out.path_len == 0);
    } else if (!strcmp(argv[1], "truncated")) {
        m.event_type = ES_EVENT_TYPE_NOTIFY_UNLINK; m.event.unlink.target = &src;
        src.path_truncated = true;
        handle(NULL, &m, self); assert(ukai_obs_gap(self));
        assert(ukai_obs_poll(self, &out)); assert(out.path_len == 0);
    } else if (!strcmp(argv[1], "drain")) {
        assert(!ukai_obs_drain(self, 0));
        assert(!ukai_obs_drain(self, 0)); // late first callback cannot satisfy second wait
        pending(); Block_release(pending); pending = NULL;
        assert(ukai_obs_drain(self, 0));
    } else if (!strcmp(argv[1], "delete")) {
        delete_result = ES_RETURN_ERROR;
        unsigned before = freed;
        assert(!ukai_obs_delete(self));
        assert(freed == before); // callback-owned ring remains allocated
        // Test fixture owns the retained allocations; never retry a real ES client.
        free(self->ring); free(self); return 0;
    } else if (!strcmp(argv[1], "overflow")) {
        m.event_type = ES_EVENT_TYPE_NOTIFY_UNLINK; m.event.unlink.target = &src;
        for (unsigned i = 0; i < UKAI_OBS_RING_CAPACITY + 7; ++i) { m.seq_num = i; m.global_seq_num = i; handle(NULL, &m, self); }
        assert(ukai_obs_gap(self));
#ifdef UKAI_OBS_HELPERS_MAX
        assert(ukai_obs_dropped(self) == 7);
        assert(!ukai_obs_invalid(self));
#else
        assert(!"base has no ring drop accounting");
#endif
    } else if (!strcmp(argv[1], "helpers")) {
#ifdef UKAI_OBS_HELPERS_MAX
        for (unsigned i = 0; i < 3; ++i) {
            process.audit_token.val[5] = 123 + i;
            assert(ukai_obs_exclude_token(self, process.audit_token.val));
        }
        m.event_type = ES_EVENT_TYPE_NOTIFY_EXEC; m.event.exec.target = &process;
        for (unsigned i = 0; i < 3; ++i) {
            process.audit_token.val[5] = 123 + i;
            handle(NULL, &m, self); assert(ukai_obs_poll(self, &out)); assert(out.ignored);
        }
        // Same launcher's pid, new exec version is workload, not a helper.
        process.audit_token.val[7]++;
        handle(NULL, &m, self); assert(ukai_obs_poll(self, &out)); assert(!out.ignored);
        equals(out.path, out.path_len, "/bin/tool");
#else
        assert(!"base excludes only supervisor");
#endif
    } else { assert(!"unknown scenario"); }
    assert(ukai_obs_delete(self));
    return 0;
}
