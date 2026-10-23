#include "obs_shim.h"
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

struct ukai_obs_client {
    es_client_t *es;
    ukai_obs_event *ring;
    _Atomic uint64_t head;
    _Atomic uint64_t tail;
    _Atomic uint64_t dropped;
    _Atomic bool gap;
    _Atomic bool invalid;
    bool subscribed;
    size_t helper_count;
    uint32_t helpers[UKAI_OBS_HELPERS_MAX][UKAI_OBS_TOKEN_WORDS];
};
static const es_event_type_t types[] = {
#define UKAI_OBS_EVENT(event, coverage, operation, meaning) ES_EVENT_TYPE_NOTIFY_##event,
#include "closed_set.def"
#undef UKAI_OBS_EVENT
};
static void mark_gap(ukai_obs_client_t *self) {
    atomic_store_explicit(&self->invalid, true, memory_order_release);
    atomic_store_explicit(&self->gap, true, memory_order_release);
}
static uint16_t copy_path(ukai_obs_client_t *self, uint8_t *out,
                          const es_file_t *file, const es_string_token_t *name) {
    if (file == NULL || file->path_truncated || file->path.length == 0 ||
        file->path.data == NULL || file->path.data[0] != '/') {
        mark_gap(self);
        return 0;
    }
    size_t size = file->path.length;
    bool slash = name != NULL && file->path.data[size - 1] != '/';
    if (name != NULL && (name->data == NULL || name->length == 0 ||
        memchr(name->data, '/', name->length) != NULL ||
        (name->length == 1 && name->data[0] == '.') ||
        (name->length == 2 && memcmp(name->data, "..", 2) == 0))) {
        mark_gap(self);
        return 0;
    }
    if (size > UKAI_OBS_PATH_MAX || (name != NULL &&
        (name->length > UKAI_OBS_PATH_MAX || size + slash + name->length > UKAI_OBS_PATH_MAX))) {
        mark_gap(self);
        return 0;
    }
    if (memchr(file->path.data, '\0', size) != NULL ||
        (name != NULL && memchr(name->data, '\0', name->length) != NULL)) {
        mark_gap(self);
        return 0;
    }
    memcpy(out, file->path.data, size);
    if (name != NULL) {
        if (slash) out[size++] = '/';
        memcpy(out + size, name->data, name->length);
        size += name->length;
    }
    return (uint16_t)size;
}
static bool excluded(const ukai_obs_client_t *self, const uint32_t token[8]) {
    for (size_t i = 0; i < self->helper_count; ++i) {
        if (memcmp(self->helpers[i], token, sizeof(self->helpers[i])) == 0) return true;
    }
    return false;
}
static void handle(es_client_t *client, const es_message_t *m, ukai_obs_client_t *self) {
    (void)client;
    if (m->version < 4) { mark_gap(self); return; }
    uint64_t head = atomic_load_explicit(&self->head, memory_order_relaxed);
    uint64_t tail = atomic_load_explicit(&self->tail, memory_order_acquire);
    if (head - tail >= UKAI_OBS_RING_CAPACITY) {
        atomic_fetch_add_explicit(&self->dropped, 1, memory_order_release);
        atomic_store_explicit(&self->gap, true, memory_order_release);
        return;
    }
    ukai_obs_event event = {0};
    event.event_type = m->event_type;
    event.global_seq = m->global_seq_num;
    event.seq = m->seq_num;
    const es_process_t *process = m->event_type == ES_EVENT_TYPE_NOTIFY_EXEC ? m->event.exec.target : m->process;
    if (process == NULL) { mark_gap(self); return; }
    memcpy(event.token, process->audit_token.val, sizeof(event.token));
    event.ignored = excluded(self, event.token);
    const es_file_t *path = NULL, *path2 = NULL;
    const es_string_token_t *name = NULL, *name2 = NULL;
    switch (m->event_type) {
    case ES_EVENT_TYPE_NOTIFY_EXEC:
        event.type = UKAI_OBS_EXEC;
        path = process->executable;
        break;
    case ES_EVENT_TYPE_NOTIFY_CREATE:
        if (m->event.create.destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
            event.type = UKAI_OBS_CREATE_DENIED;
            path = m->event.create.destination.new_path.dir;
            name = &m->event.create.destination.new_path.filename;
        } else if (m->event.create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
            event.type = UKAI_OBS_CREATE;
            path = m->event.create.destination.existing_file;
        } else { mark_gap(self); return; }
        break;
    case ES_EVENT_TYPE_NOTIFY_RENAME:
        event.type = UKAI_OBS_RENAME;
        path = m->event.rename.source;
        if (m->event.rename.destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
            path2 = m->event.rename.destination.new_path.dir;
            name2 = &m->event.rename.destination.new_path.filename;
        } else if (m->event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
            path2 = m->event.rename.destination.existing_file;
        } else { mark_gap(self); return; }
        break;
    case ES_EVENT_TYPE_NOTIFY_LINK:
        event.type = UKAI_OBS_LINK;
        path = m->event.link.source;
        path2 = m->event.link.target_dir;
        name2 = &m->event.link.target_filename;
        break;
    case ES_EVENT_TYPE_NOTIFY_UNLINK:
        event.type = UKAI_OBS_UNLINK; path = m->event.unlink.target; break;
    case ES_EVENT_TYPE_NOTIFY_TRUNCATE:
        event.type = UKAI_OBS_TRUNCATE; path = m->event.truncate.target; break;
    case ES_EVENT_TYPE_NOTIFY_SETATTRLIST:
        event.type = UKAI_OBS_SETATTRLIST; path = m->event.setattrlist.target; break;
    case ES_EVENT_TYPE_NOTIFY_SETMODE:
        event.type = UKAI_OBS_SETMODE; path = m->event.setmode.target; break;
    case ES_EVENT_TYPE_NOTIFY_CLONE:
        event.type = UKAI_OBS_CLONE; path = m->event.clone.source;
        path2 = m->event.clone.target_dir; name2 = &m->event.clone.target_name; break;
    case ES_EVENT_TYPE_NOTIFY_COPYFILE:
        event.type = UKAI_OBS_COPYFILE; path = m->event.copyfile.source;
        if (m->event.copyfile.target_file != NULL) path2 = m->event.copyfile.target_file;
        else { path2 = m->event.copyfile.target_dir; name2 = &m->event.copyfile.target_name; }
        break;
    case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
        event.type = UKAI_OBS_EXCHANGEDATA;
        path = m->event.exchangedata.file1; path2 = m->event.exchangedata.file2; break;
    case ES_EVENT_TYPE_NOTIFY_SETEXTATTR:
        event.type = UKAI_OBS_METADATA; path = m->event.setextattr.target; break;
    case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR:
        event.type = UKAI_OBS_METADATA; path = m->event.deleteextattr.target; break;
    case ES_EVENT_TYPE_NOTIFY_UTIMES:
        event.type = UKAI_OBS_METADATA; path = m->event.utimes.target; break;
    case ES_EVENT_TYPE_NOTIFY_SETOWNER:
        event.type = UKAI_OBS_METADATA; path = m->event.setowner.target; break;
    case ES_EVENT_TYPE_NOTIFY_SETFLAGS:
        event.type = UKAI_OBS_METADATA; path = m->event.setflags.target; break;
    case ES_EVENT_TYPE_NOTIFY_SETACL:
        event.type = UKAI_OBS_METADATA; path = m->event.setacl.target; break;
    case ES_EVENT_TYPE_NOTIFY_CLOSE:
        event.modified = m->event.close.modified;
        event.type = event.modified ? UKAI_OBS_WRITE : UKAI_OBS_CLOSE_UNMODIFIED;
        event.ignored |= !event.modified;
        path = m->event.close.target;
        break;
    default: mark_gap(self); return;
    }
    if (!event.ignored) {
        event.path_len = copy_path(self, event.path, path, name);
        if (event.type == UKAI_OBS_RENAME || event.type == UKAI_OBS_LINK ||
            event.type == UKAI_OBS_CLONE || event.type == UKAI_OBS_COPYFILE ||
            event.type == UKAI_OBS_EXCHANGEDATA)
            event.path2_len = copy_path(self, event.path2, path2, name2);
    }
    // Even unmodified CLOSE and helper messages consume sequence numbers.
    self->ring[head % UKAI_OBS_RING_CAPACITY] = event;
    atomic_store_explicit(&self->head, head + 1, memory_order_release);
}
int32_t ukai_obs_new_descendants(ukai_obs_client_t **out) {
    *out = NULL;
    ukai_obs_client_t *self = calloc(1, sizeof(*self));
    if (self == NULL) return (int32_t)ES_NEW_CLIENT_RESULT_ERR_INTERNAL;
    self->ring = calloc(UKAI_OBS_RING_CAPACITY, sizeof(ukai_obs_event));
    if (self->ring == NULL) { free(self); return (int32_t)ES_NEW_CLIENT_RESULT_ERR_INTERNAL; }
    ukai_obs_client_t *captured = self;
    es_new_client_result_t result = es_new_descendants_client(&self->es, ^(es_client_t *client, const es_message_t *m) {
        handle(client, m, captured);
    });
    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        free(self->ring); free(self); return (int32_t)result;
    }
    *out = self;
    return (int32_t)result;
}

bool ukai_obs_unmute_all(ukai_obs_client_t *client) {
    return es_unmute_all_paths(client->es) == ES_RETURN_SUCCESS &&
           es_unmute_all_target_paths(client->es) == ES_RETURN_SUCCESS;
}

bool ukai_obs_muted_paths_events(ukai_obs_client_t *client, uint32_t event_type) {
    es_muted_paths_t *muted = NULL;
    if (es_muted_paths_events(client->es, &muted) != ES_RETURN_SUCCESS) {
        return true; /* Fail closed: unreadable mute state refuses the client. */
    }
    bool still_muted = false;
    for (size_t i = 0; i < muted->count && !still_muted; ++i) {
        const es_muted_path_t *path = &muted->paths[i];
        for (size_t j = 0; j < path->event_count; ++j) {
            if ((uint32_t)path->events[j] == event_type) {
                still_muted = true;
                break;
            }
        }
    }
    es_release_muted_paths(muted);
    return still_muted;
}


bool ukai_obs_mute_self(ukai_obs_client_t *client) {
    audit_token_t self_token;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&self_token, &count) != KERN_SUCCESS) {
        return false;
    }
    return es_mute_process(client->es, &self_token) == ES_RETURN_SUCCESS;
}


bool ukai_obs_poll(ukai_obs_client_t *client, ukai_obs_event *out) {
    uint64_t tail = atomic_load_explicit(&client->tail, memory_order_relaxed);
    uint64_t head = atomic_load_explicit(&client->head, memory_order_acquire);
    if (tail == head) {
        return false;
    }
    *out = client->ring[tail % UKAI_OBS_RING_CAPACITY];
    atomic_store_explicit(&client->tail, tail + 1, memory_order_release);
    return true;
}

bool ukai_obs_gap(const ukai_obs_client_t *client) {
    return atomic_load_explicit(&client->gap, memory_order_acquire);
}

bool ukai_obs_verify_unmuted(ukai_obs_client_t *client) {
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); ++i)
        if (ukai_obs_muted_paths_events(client, types[i])) return false;
    return true;
}
bool ukai_obs_subscribe(ukai_obs_client_t *client) {
    client->subscribed = true; // freeze helper table before any callback
    return es_subscribe(client->es, types, sizeof(types) / sizeof(types[0])) == ES_RETURN_SUCCESS;
}
bool ukai_obs_exclude_token(ukai_obs_client_t *client, const uint32_t token[8]) {
    if (client->subscribed || client->helper_count >= UKAI_OBS_HELPERS_MAX || token[5] == 0) return false;
    if (!excluded(client, token)) memcpy(client->helpers[client->helper_count++], token, sizeof(client->helpers[0]));
    return true;
}
bool ukai_obs_invalid(const ukai_obs_client_t *client) {
    return atomic_load_explicit(&client->invalid, memory_order_acquire);
}
uint64_t ukai_obs_dropped(const ukai_obs_client_t *client) {
    return atomic_load_explicit(&client->dropped, memory_order_acquire);
}
bool ukai_obs_drain(ukai_obs_client_t *client, uint32_t timeout_ms) {
    // A fresh semaphore belongs only to this sync. A callback arriving after
    // timeout cannot satisfy another wait, and holds no pointer to the client.
    dispatch_semaphore_t synced = dispatch_semaphore_create(0);
    if (synced == NULL) return false;
    dispatch_retain(synced); // callback reference, including after timeout
    if (es_sync_client(client->es, ^{ dispatch_semaphore_signal(synced); dispatch_release(synced); }) != ES_RETURN_SUCCESS) {
        dispatch_release(synced);
        dispatch_release(synced);
        return false;
    }
    bool done = dispatch_semaphore_wait(synced,
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)timeout_ms * NSEC_PER_MSEC)) == 0;
    dispatch_release(synced);
    return done;
}
bool ukai_obs_delete(ukai_obs_client_t *client) {
    // ES says its pointer is invalid after delete, even on an error. Never
    // retry it; retain the handler's backing state on shutdown failure rather
    // than risking callbacks into freed memory. Caller records the failure.
    if (es_delete_client(client->es) != ES_RETURN_SUCCESS) return false;
    free(client->ring);
    free(client);
    return true;
}
