#include "shim.h"

#include <dispatch/dispatch.h>
#include <Block.h>
#include <errno.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <libproc.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>

_Static_assert(sizeof(ukai_es_event) == 64, "custody events are fixed 64-byte records (§4.1 rule 3)");

/*
 * The handler thread writes ring slots and the head index; the custodian
 * thread reads slots and the tail index. Release/acquire on the two indexes
 * publishes each slot before it is read. Everything else is written by the
 * handler only, or by the custodian before the first event.
 */
struct ukai_es_client {
    es_client_t *es;
    dispatch_semaphore_t synced;
    void (^sync_block)(void); /* One heap block, allocated before release. */
    _Atomic uint64_t sync_issued;
    _Atomic uint64_t sync_completed;
    ukai_es_event *ring; /* UKAI_ES_RING_CAPACITY slots, allocated once. */
    _Atomic uint64_t head;
    _Atomic uint64_t tail;
    _Atomic bool gap; /* Sticky: overflow, malformed message or wrong event set. */
    _Atomic uint64_t guard_denials;
};

static void mark_gap(ukai_es_client_t *self) {
    atomic_store_explicit(&self->gap, true, memory_order_release);
}

static void push(ukai_es_client_t *self, int32_t type, const es_message_t *m,
                 const es_process_t *process, int32_t exit_status) {
    uint64_t head = atomic_load_explicit(&self->head, memory_order_relaxed);
    uint64_t tail = atomic_load_explicit(&self->tail, memory_order_acquire);
    if (head - tail >= UKAI_ES_RING_CAPACITY) {
        /* Full ring: drop the event and raise the sticky gap flag. The
         * handler never blocks; the stop treats the stream as gapped
         * (§4.4: any gap marks the stream gapped for the attempt). */
        mark_gap(self);
        return;
    }
    ukai_es_event event = {
        .type = type,
        .global_seq = m->global_seq_num,
        .seq = m->seq_num,
        .exit_status = exit_status,
    };
    for (int i = 0; i < UKAI_ES_TOKEN_WORDS; ++i) {
        event.token[i] = process->audit_token.val[i];
    }
    self->ring[head % UKAI_ES_RING_CAPACITY] = event;
    atomic_store_explicit(&self->head, head + 1, memory_order_release);
}

static void handle_auth(ukai_es_client_t *self, es_client_t *client, const es_message_t *m) {
    /* Deny inline, never cache (§4.5 step 1): every request the guard client
     * delivers comes from a member, and every answer is a denial. Fail-closed
     * mode answers a missed deadline by itself and never kills the client. */
    es_respond_auth_result(client, m, ES_AUTH_RESULT_DENY, false);
    atomic_fetch_add_explicit(&self->guard_denials, 1, memory_order_relaxed);
}

static void handle(es_client_t *client, const es_message_t *m, ukai_es_client_t *self) {
    switch (m->event_type) {
    case ES_EVENT_TYPE_AUTH_SIGNAL:
    case ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME:
    case ES_EVENT_TYPE_AUTH_EXEC:
        handle_auth(self, client, m);
        return;
    default:
        break;
    }
    if (m->version < 4) {
        /* The prototype's measured rule: a message too old to carry the
         * custody fields cannot be trusted; treat the stream as gapped. */
        mark_gap(self);
        return;
    }
    switch (m->event_type) {
    case ES_EVENT_TYPE_NOTIFY_FORK:
        push(self, UKAI_ES_EVENT_FORK, m, m->event.fork.child, 0);
        return;
    case ES_EVENT_TYPE_NOTIFY_EXEC:
        push(self, UKAI_ES_EVENT_EXEC, m, m->event.exec.target, 0);
        return;
    case ES_EVENT_TYPE_NOTIFY_EXIT:
        /* The wait status is read as a fixed int, never dereferenced further. */
        push(self, UKAI_ES_EVENT_EXIT, m, m->process, (int32_t)m->event.exit.stat);
        return;
    default:
        /* Custody clients subscribe three events and nothing else (§4.1
         * rule 3); anything else is a stream this code cannot trust. */
        mark_gap(self);
        return;
    }
}

int32_t ukai_es_new_descendants(ukai_es_client_t **out) {
    *out = NULL;
    /* The last allocations of the custody path (§4.1 rule 4). */
    ukai_es_client_t *self = calloc(1, sizeof(*self));
    if (self == NULL) {
        return (int32_t)ES_NEW_CLIENT_RESULT_ERR_INTERNAL;
    }
    self->ring = calloc(UKAI_ES_RING_CAPACITY, sizeof(ukai_es_event));
    self->synced = dispatch_semaphore_create(0);
    if (self->ring == NULL || self->synced == NULL) {
        free(self->ring);
        if (self->synced != NULL) {
            dispatch_release(self->synced);
        }
        free(self);
        return (int32_t)ES_NEW_CLIENT_RESULT_ERR_INTERNAL;
    }
    ukai_es_client_t *captured = self;
    self->sync_block = Block_copy(^{
        uint64_t generation = atomic_load_explicit(&captured->sync_issued, memory_order_acquire);
        atomic_store_explicit(&captured->sync_completed, generation, memory_order_release);
        dispatch_semaphore_signal(captured->synced);
    });
    if (self->sync_block == NULL) {
        free(self->ring);
        dispatch_release(self->synced);
        free(self);
        return (int32_t)ES_NEW_CLIENT_RESULT_ERR_INTERNAL;
    }
    es_new_client_result_t result = es_new_descendants_client(&self->es, ^(es_client_t *client, const es_message_t *m) {
        handle(client, m, captured);
    });
    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        Block_release(self->sync_block);
        free(self->ring);
        dispatch_release(self->synced);
        free(self);
        return (int32_t)result;
    }
    *out = self;
    return (int32_t)result;
}

bool ukai_es_unmute_all(ukai_es_client_t *client) {
    return es_unmute_all_paths(client->es) == ES_RETURN_SUCCESS &&
           es_unmute_all_target_paths(client->es) == ES_RETURN_SUCCESS;
}

static bool custody_event_type(uint32_t kind, es_event_type_t *out) {
    switch (kind) {
    case UKAI_ES_EVENT_FORK: *out = ES_EVENT_TYPE_NOTIFY_FORK; return true;
    case UKAI_ES_EVENT_EXEC: *out = ES_EVENT_TYPE_NOTIFY_EXEC; return true;
    case UKAI_ES_EVENT_EXIT: *out = ES_EVENT_TYPE_NOTIFY_EXIT; return true;
    default: return false;
    }
}

bool ukai_es_muted_paths_events(ukai_es_client_t *client, uint32_t event_type) {
    es_event_type_t sdk_type;
    if (!custody_event_type(event_type, &sdk_type)) { return true; }
    es_muted_paths_t *muted = NULL;
    if (es_muted_paths_events(client->es, &muted) != ES_RETURN_SUCCESS) {
        return true; /* Fail closed: unreadable mute state refuses the client. */
    }
    bool still_muted = false;
    for (size_t i = 0; i < muted->count && !still_muted; ++i) {
        const es_muted_path_t *path = &muted->paths[i];
        for (size_t j = 0; j < path->event_count; ++j) {
            if (path->events[j] == sdk_type) {
                still_muted = true;
                break;
            }
        }
    }
    es_release_muted_paths(muted);
    return still_muted;
}

bool ukai_es_subscribe_custody(ukai_es_client_t *client) {
    const es_event_type_t types[] = {
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_EXIT,
    };
    return es_subscribe(client->es, types, 3) == ES_RETURN_SUCCESS;
}

bool ukai_es_prepare_guard(ukai_es_client_t *client) {
    /* Fail-closed: set, then read back (§4.3 step 3). A late or dropped
     * answer is denied, and the client is never killed. */
    es_deadline_miss_mode_t mode = (es_deadline_miss_mode_t)ES_DEADLINE_MISS_MODE_KILL;
    if (es_set_deadline_miss_mode(client->es, ES_DEADLINE_MISS_MODE_FAIL_CLOSED) != ES_RETURN_SUCCESS) {
        return false;
    }
    if (es_get_deadline_miss_mode(client->es, &mode) != ES_RETURN_SUCCESS ||
        mode != ES_DEADLINE_MISS_MODE_FAIL_CLOSED) {
        return false;
    }
    return true;
}

bool ukai_es_subscribe_guard(ukai_es_client_t *client) {
    const es_event_type_t types[] = {
        ES_EVENT_TYPE_AUTH_SIGNAL,
        ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME,
        ES_EVENT_TYPE_AUTH_EXEC,
    };
    return es_subscribe(client->es, types, 3) == ES_RETURN_SUCCESS;
}

bool ukai_es_mute_self(ukai_es_client_t *client) {
    audit_token_t self_token;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&self_token, &count) != KERN_SUCCESS) {
        return false;
    }
    return es_mute_process(client->es, &self_token) == ES_RETURN_SUCCESS;
}

bool ukai_es_poll(ukai_es_client_t *client, ukai_es_event *out) {
    uint64_t tail = atomic_load_explicit(&client->tail, memory_order_relaxed);
    uint64_t head = atomic_load_explicit(&client->head, memory_order_acquire);
    if (tail == head) {
        return false;
    }
    *out = client->ring[tail % UKAI_ES_RING_CAPACITY];
    atomic_store_explicit(&client->tail, tail + 1, memory_order_release);
    return true;
}

bool ukai_es_ring_overflowed(ukai_es_client_t *client) {
    return atomic_load_explicit(&client->gap, memory_order_acquire);
}

/* A semaphore wake is only a hint. The generation is the evidence: a late
 * callback for a timed-out request cannot complete a later request. At most
 * one marker is outstanding; ES retains the preallocated heap block without
 * copying a new stack block on every drain. The caller is single-threaded. */
static bool wait_sync(ukai_es_client_t *client, uint64_t generation, dispatch_time_t deadline) {
    while (atomic_load_explicit(&client->sync_completed, memory_order_acquire) < generation) {
        if (dispatch_semaphore_wait(client->synced, deadline) != 0) {
            return atomic_load_explicit(&client->sync_completed, memory_order_acquire) >= generation;
        }
    }
    return true;
}

bool ukai_es_drain(ukai_es_client_t *client, uint32_t timeout_ms) {
    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, (int64_t)timeout_ms * NSEC_PER_MSEC);
    uint64_t previous = atomic_load_explicit(&client->sync_issued, memory_order_acquire);
    if (!wait_sync(client, previous, deadline) || previous == UINT64_MAX) {
        return false;
    }
    uint64_t generation = previous + 1;
    atomic_store_explicit(&client->sync_issued, generation, memory_order_release);
    if (es_sync_client(client->es, client->sync_block) != ES_RETURN_SUCCESS) {
        atomic_store_explicit(&client->sync_issued, previous, memory_order_release);
        return false;
    }
    return wait_sync(client, generation, deadline);
}

uint64_t ukai_es_guard_denials(const ukai_es_client_t *client) {
    return atomic_load_explicit(&client->guard_denials, memory_order_relaxed);
}

int32_t ukai_es_signal(const uint32_t token[UKAI_ES_TOKEN_WORDS], int32_t sig) {
    audit_token_t audit_token;
    for (int i = 0; i < UKAI_ES_TOKEN_WORDS; ++i) {
        audit_token.val[i] = token[i];
    }
    return (int32_t)proc_signal_with_audittoken(&audit_token, sig);
}

bool ukai_es_self_token(uint32_t out[UKAI_ES_TOKEN_WORDS]) {
    audit_token_t token;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&token, &count) != KERN_SUCCESS) {
        return false;
    }
    for (int i = 0; i < UKAI_ES_TOKEN_WORDS; ++i) {
        out[i] = token.val[i];
    }
    return true;
}

uint64_t ukai_es_continuous_time(void) {
    return (uint64_t)mach_continuous_time();
}

bool ukai_es_delete(ukai_es_client_t *client) {
    bool deleted = es_delete_client(client->es) == ES_RETURN_SUCCESS;
    /* A failed delete may still deliver callbacks. Keep their backing memory
     * alive rather than freeing a live handler/sync capture. */
    if (!deleted) { return false; }
    Block_release(client->sync_block);
    free(client->ring);
    dispatch_release(client->synced);
    free(client);
    return deleted;
}
