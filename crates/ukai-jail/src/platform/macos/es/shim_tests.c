/* Entitlement-free tests of the real shim against SDK-typed stand-ins. */
#define es_muted_paths_events fake_muted_paths
#define es_release_muted_paths fake_release_paths
#define es_sync_client fake_sync
#define es_set_deadline_miss_mode fake_set_mode
#define es_get_deadline_miss_mode fake_get_mode
#define es_subscribe fake_subscribe
#define es_new_descendants_client fake_new
#define es_delete_client fake_delete
#include "shim.c"
#include <Block.h>
#include <assert.h>
#include <string.h>

static es_event_type_t muted_type;
static void (^pending_sync)(void);
static unsigned sync_calls;
static unsigned set_calls, get_calls, subscriptions;
static unsigned mode_failure;
static bool sync_failure, delete_failure, complete_on_delete;
static void complete_sync(void);
es_return_t fake_set_mode(es_client_t *client, es_deadline_miss_mode_t mode) {
    (void)client;
    assert(mode == ES_DEADLINE_MISS_MODE_FAIL_CLOSED);
    set_calls++;
    return mode_failure == 1 ? ES_RETURN_ERROR : ES_RETURN_SUCCESS;
}
es_return_t fake_get_mode(es_client_t *client, es_deadline_miss_mode_t *mode) {
    (void)client;
    get_calls++;
    *mode = mode_failure == 3 ? ES_DEADLINE_MISS_MODE_KILL : ES_DEADLINE_MISS_MODE_FAIL_CLOSED;
    return mode_failure == 2 ? ES_RETURN_ERROR : ES_RETURN_SUCCESS;
}
es_return_t fake_subscribe(es_client_t *client, const es_event_type_t *events, uint32_t count) {
    (void)client;
    assert(count == 3 && events[0] == ES_EVENT_TYPE_AUTH_SIGNAL);
    subscriptions++;
    return ES_RETURN_SUCCESS;
}

es_return_t fake_muted_paths(es_client_t *client, es_muted_paths_t **out) {
    (void)client;
    static es_muted_path_t path;
    static es_muted_paths_t paths;
    path.event_count = 1;
    path.events = &muted_type;
    paths.count = 1;
    paths.paths = &path;
    *out = &paths;
    return ES_RETURN_SUCCESS;
}
void fake_release_paths(es_muted_paths_t *paths) { (void)paths; }
es_return_t fake_sync(es_client_t *client, void (^block)(void)) {
    (void)client;
    assert(pending_sync == NULL);
    if (sync_failure) { return ES_RETURN_ERROR; }
    pending_sync = Block_copy(block);
    sync_calls++;
    return ES_RETURN_SUCCESS;
}
es_new_client_result_t fake_new(es_client_t **out, es_handler_block_t handler) {
    (void)handler;
    *out = (es_client_t *)1;
    return ES_NEW_CLIENT_RESULT_SUCCESS;
}
es_return_t fake_delete(es_client_t *client) {
    (void)client;
    if (delete_failure) { return ES_RETURN_ERROR; }
    if (complete_on_delete) { complete_sync(); }
    return ES_RETURN_SUCCESS;
}
static void complete_sync(void) {
    assert(pending_sync != NULL);
    void (^block)(void) = pending_sync;
    pending_sync = NULL;
    block();
    Block_release(block);
}
int main(int argc, char **argv) {
    assert(argc == 2);
    ukai_es_client_t *client = NULL;
    assert(ukai_es_new_descendants(&client) == ES_NEW_CLIENT_RESULT_SUCCESS);
    if (strcmp(argv[1], "mapping") == 0) {
        const es_event_type_t sdk[] = {ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_EXIT};
        const uint32_t internal[] = {UKAI_ES_EVENT_FORK, UKAI_ES_EVENT_EXEC, UKAI_ES_EVENT_EXIT};
        for (unsigned i = 0; i < 3; i++) {
            muted_type = sdk[i];
            assert(ukai_es_muted_paths_events(client, internal[i]));
            for (unsigned j = 0; j < 3; j++) {
                if (j != i) assert(!ukai_es_muted_paths_events(client, internal[j]));
            }
        }
    } else if (strcmp(argv[1], "sync") == 0) {
        assert(!ukai_es_drain(client, 0));
        complete_sync(); // Previous drain timed out; this wake is stale.
        assert(!ukai_es_drain(client, 0));
        assert(sync_calls == 2);
        // Repeated polling while a marker is outstanding must not enqueue
        // additional blocks (or mistake an old semaphore wake for this one).
#ifdef UKAI_SYNC_REUSE_TEST
        for (int i = 0; i < 100; i++) assert(!ukai_es_drain(client, 0));
        assert(sync_calls == 2);
#endif
        complete_sync();
    } else if (strcmp(argv[1], "pending-sync-delete") == 0) {
        assert(!ukai_es_drain(client, 0));
        assert(ukai_es_delete(client));
        // A successful delete is not evidence that an already queued sync
        // callback cannot run. ASan checks the actual late callback accesses.
        complete_sync();
        return 0;
    } else if (strcmp(argv[1], "sync-error") == 0) {
        sync_failure = true;
        for (int i = 0; i < 100; i++) assert(!ukai_es_drain(client, 0));
        assert(atomic_load(&client->sync->references) == 1);
        assert(atomic_load(&client->sync->issued) == 0);
        sync_failure = false;
        assert(!ukai_es_drain(client, 0));
        complete_sync();
        assert(atomic_load(&client->sync->references) == 1);
    } else if (strcmp(argv[1], "delete-error") == 0) {
        assert(!ukai_es_drain(client, 0));
        delete_failure = true;
        assert(!ukai_es_delete(client));
        complete_sync();
        assert(atomic_load(&client->sync->references) == 1);
        delete_failure = false;
    } else if (strcmp(argv[1], "sync-during-delete") == 0) {
        assert(!ukai_es_drain(client, 0));
        complete_on_delete = true;
    } else if (strcmp(argv[1], "invalid-version") == 0) {
        es_message_t message = {.version = 3, .event_type = ES_EVENT_TYPE_NOTIFY_FORK};
        handle(client->es, &message, client);
        assert(ukai_es_ring_overflowed(client));
        ukai_es_event event;
        assert(!ukai_es_poll(client, &event));
    } else if (strcmp(argv[1], "overflow") == 0) {
        atomic_store(&client->head, UKAI_ES_RING_CAPACITY);
        es_message_t message = {.version = 4};
        es_process_t process = {0};
        push(client, UKAI_ES_EVENT_FORK, &message, &process, 0);
        assert(ukai_es_ring_overflowed(client));
        assert(atomic_load(&client->head) == UKAI_ES_RING_CAPACITY);
    } else if (strcmp(argv[1], "guard") == 0) {
        for (mode_failure = 1; mode_failure <= 3; mode_failure++) {
            assert(!ukai_es_prepare_guard(client));
            assert(subscriptions == 0);
        }
        assert(set_calls == 3 && get_calls == 2);
        mode_failure = 0;
        assert(ukai_es_prepare_guard(client));
        assert(subscriptions == 0); // Still unarmed at readiness.
        assert(ukai_es_subscribe_guard(client));
        assert(set_calls == 4 && get_calls == 3 && subscriptions == 1);
    } else { assert(0); }
    assert(ukai_es_delete(client));
    return 0;
}
