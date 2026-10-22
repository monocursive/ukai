#include "obs_shim.h"

#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

/*
 * The same ring discipline as the custody shim (§4.1): the handler thread
 * writes ring slots and the head index; the supervisor thread reads slots
 * and the tail index. Release/acquire on the two indexes publishes each
 * slot before it is read. The gap flag is sticky.
 */
struct ukai_obs_client {
    es_client_t *es;
    dispatch_semaphore_t synced;
    ukai_obs_event *ring; /* UKAI_OBS_RING_CAPACITY slots, allocated once. */
    _Atomic uint64_t head;
    _Atomic uint64_t tail;
    _Atomic bool gap;
};

static void mark_gap(ukai_obs_client_t *self) {
    atomic_store_explicit(&self->gap, true, memory_order_release);
}

/* Copies one es_string_token_t into the slot's fixed path buffer. A path the
 * buffer cannot hold whole is not evidence (§11.3: say what the path was or
 * say nothing), so it marks the stream gapped instead. */
static void push_path(ukai_obs_client_t *self, int32_t type, const es_message_t *m,
                      const es_process_t *process, const es_string_token_t *path,
                      int32_t modified) {
    uint64_t head = atomic_load_explicit(&self->head, memory_order_relaxed);
    uint64_t tail = atomic_load_explicit(&self->tail, memory_order_acquire);
    if (head - tail >= UKAI_OBS_RING_CAPACITY) {
        /* Full ring: drop the event and raise the sticky gap flag; the
         * handler never blocks (§4.1 rule 4). */
        mark_gap(self);
        return;
    }
    ukai_obs_event event;
    memset(&event, 0, sizeof(event));
    event.type = type;
    event.global_seq = m->global_seq_num;
    event.seq = m->seq_num;
    event.modified = modified;
    if (process != NULL) {
        for (int i = 0; i < UKAI_OBS_TOKEN_WORDS; ++i) {
            event.token[i] = process->audit_token.val[i];
        }
    }
    if (path != NULL) {
        if (path->length >= UKAI_OBS_PATH_MAX) {
            mark_gap(self);
            return;
        }
        event.path_len = (uint16_t)path->length;
        memcpy(event.path, path->data, path->length);
    }
    self->ring[head % UKAI_OBS_RING_CAPACITY] = event;
    atomic_store_explicit(&self->head, head + 1, memory_order_release);
}

static const es_string_token_t *file_path(const es_file_t *file) {
    return file == NULL ? NULL : &file->path;
}

static void handle(es_client_t *client, const es_message_t *m, ukai_obs_client_t *self) {
    (void)client;
    if (m->version < 4) {
        /* The custody shim's measured rule: a message too old to carry the
         * sequencing fields cannot be trusted; the stream is gapped. */
        mark_gap(self);
        return;
    }
    switch (m->event_type) {
    case ES_EVENT_TYPE_NOTIFY_EXEC:
        push_path(self, UKAI_OBS_EXEC, m, m->event.exec.target,
                  file_path(m->event.exec.target->executable), 0);
        return;
    case ES_EVENT_TYPE_NOTIFY_CREATE:
        /* NOTIFY_CREATE usually arrives after the object exists, so the
         * destination is usually an existing file; a NEW_PATH destination
         * carries dir + filename, and only the filename is a path this
         * event can name (obs_shim.h: one interesting path). */
        if (m->event.create.destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
            push_path(self, UKAI_OBS_CREATE, m, m->process,
                      &m->event.create.destination.new_path.filename, 0);
        } else {
            push_path(self, UKAI_OBS_CREATE, m, m->process,
                      file_path(m->event.create.destination.existing_file), 0);
        }
        return;
    case ES_EVENT_TYPE_NOTIFY_RENAME:
        /* The destination is the state the workspace takes on; the source is
         * not carried (see obs_shim.h). A NEW_PATH destination names dir +
         * filename; the filename is the path this event can name. */
        if (m->event.rename.destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
            push_path(self, UKAI_OBS_RENAME, m, m->process,
                      &m->event.rename.destination.new_path.filename, 0);
        } else {
            push_path(self, UKAI_OBS_RENAME, m, m->process,
                      file_path(m->event.rename.destination.existing_file), 0);
        }
        return;
    case ES_EVENT_TYPE_NOTIFY_UNLINK:
        push_path(self, UKAI_OBS_UNLINK, m, m->process, file_path(m->event.unlink.target), 0);
        return;
    case ES_EVENT_TYPE_NOTIFY_LINK:
        push_path(self, UKAI_OBS_WRITE, m, m->process, &m->event.link.target_filename, 0);
        return;
    case ES_EVENT_TYPE_NOTIFY_TRUNCATE:
        push_path(self, UKAI_OBS_WRITE, m, m->process, file_path(m->event.truncate.target), 0);
        return;
    case ES_EVENT_TYPE_NOTIFY_SETATTRLIST:
        push_path(self, UKAI_OBS_WRITE, m, m->process, file_path(m->event.setattrlist.target), 0);
        return;
    case ES_EVENT_TYPE_NOTIFY_SETMODE:
        push_path(self, UKAI_OBS_WRITE, m, m->process, file_path(m->event.setmode.target), 0);
        return;
    case ES_EVENT_TYPE_NOTIFY_CLOSE:
        /* §5: CLOSE counts when `modified` is set and nowhere else; an
         * unmodified close is not evidence and not a gap. */
        if (m->event.close.modified) {
            push_path(self, UKAI_OBS_WRITE, m, m->process, file_path(m->event.close.target), 1);
        }
        return;
    default:
        /* §5 fixes the subscription set; anything else is a stream this
         * code cannot trust. */
        mark_gap(self);
        return;
    }
}

int32_t ukai_obs_new_descendants(ukai_obs_client_t **out) {
    *out = NULL;
    /* The last allocations of the observation path (§4.1 rule 4). */
    ukai_obs_client_t *self = calloc(1, sizeof(*self));
    if (self == NULL) {
        return (int32_t)ES_NEW_CLIENT_RESULT_ERR_INTERNAL;
    }
    self->ring = calloc(UKAI_OBS_RING_CAPACITY, sizeof(ukai_obs_event));
    self->synced = dispatch_semaphore_create(0);
    if (self->ring == NULL || self->synced == NULL) {
        free(self->ring);
        if (self->synced != NULL) {
            dispatch_release(self->synced);
        }
        free(self);
        return (int32_t)ES_NEW_CLIENT_RESULT_ERR_INTERNAL;
    }
    ukai_obs_client_t *captured = self;
    es_new_client_result_t result = es_new_descendants_client(&self->es, ^(es_client_t *client, const es_message_t *m) {
        handle(client, m, captured);
    });
    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        free(self->ring);
        dispatch_release(self->synced);
        free(self);
        return (int32_t)result;
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

bool ukai_obs_subscribe(ukai_obs_client_t *client) {
    const es_event_type_t types[] = {
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_CREATE,
        ES_EVENT_TYPE_NOTIFY_RENAME,
        ES_EVENT_TYPE_NOTIFY_UNLINK,
        ES_EVENT_TYPE_NOTIFY_LINK,
        ES_EVENT_TYPE_NOTIFY_TRUNCATE,
        ES_EVENT_TYPE_NOTIFY_SETATTRLIST,
        ES_EVENT_TYPE_NOTIFY_SETMODE,
        ES_EVENT_TYPE_NOTIFY_CLOSE,
    };
    return es_subscribe(client->es, types, 9) == ES_RETURN_SUCCESS;
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

bool ukai_obs_drain(ukai_obs_client_t *client, uint32_t timeout_ms) {
    if (es_sync_client(client->es, ^{ dispatch_semaphore_signal(client->synced); }) != ES_RETURN_SUCCESS) {
        return false;
    }
    return dispatch_semaphore_wait(client->synced,
               dispatch_time(DISPATCH_TIME_NOW, (int64_t)timeout_ms * NSEC_PER_MSEC)) == 0;
}

bool ukai_obs_delete(ukai_obs_client_t *client) {
    bool deleted = es_delete_client(client->es) == ES_RETURN_SUCCESS;
    free(client->ring);
    dispatch_release(client->synced);
    free(client);
    return deleted;
}
