/*
 * Endpoint Security observation shim (jail-macos.md §5, J17).
 *
 * The supervisor's third ES client: the observation client of §5, which
 * carries the `exec` and `fs.write` classes and nothing else. It differs
 * from the custody shim in one deliberate way: it reads paths, because
 * §11.3 evidence names what was touched. The rule the custody shim's
 * "never reads a path" carries (§4.1 rule 3) is a custody rule — the
 * custody handlers must never block on workload-controlled data — and it
 * holds here too: the handler copies at most UKAI_OBS_PATH_MAX bytes of a
 * path into a preallocated slot and never dereferences further, so the
 * handler stays allocation-free and non-blocking.
 */
#ifndef UKAI_OBS_SHIM_H
#define UKAI_OBS_SHIM_H

#include <EndpointSecurity/EndpointSecurity.h>
#include <stdbool.h>
#include <stdint.h>

#define UKAI_OBS_RING_CAPACITY 16384u
#define UKAI_OBS_PATH_MAX 1024u
#define UKAI_OBS_TOKEN_WORDS 8

/* Shim-internal observation event numbers; Rust counts on this mapping. */
enum {
    UKAI_OBS_EXEC = 1,
    UKAI_OBS_CREATE = 2,
    UKAI_OBS_WRITE = 3,  /* CLOSE(modified), TRUNCATE, SETATTRLIST, SETMODE, LINK. */
    UKAI_OBS_RENAME = 4,
    UKAI_OBS_UNLINK = 5,
};

typedef struct ukai_obs_client ukai_obs_client_t;

/* The fixed observation record. `path` holds the event's one interesting
 * path (§11.3), truncated at UKAI_OBS_PATH_MAX — a path longer than the
 * buffer marks the stream gapped rather than reporting a path that is not
 * the one that was named. For RENAME this is the destination; the source is
 * not carried, and the event says so (§11.3 says what may be said, no more). */
typedef struct {
    int32_t type;
    uint64_t global_seq;
    uint64_t seq;
    uint32_t token[UKAI_OBS_TOKEN_WORDS];
    int32_t modified; /* CLOSE's modified flag; 0 elsewhere. */
    uint16_t path_len;
    uint8_t path[UKAI_OBS_PATH_MAX];
} ukai_obs_event;

/* Creates a descendants observation client and its preallocated ring.
 * Allocates its last memory here; nothing below allocates. Returns the raw
 * es_new_client_result_t so Rust can map the result codes. */
int32_t ukai_obs_new_descendants(ukai_obs_client_t **out);

/* es_unmute_all_paths + es_unmute_all_target_paths. */
bool ukai_obs_unmute_all(ukai_obs_client_t *client);

/* Whether `event_type` is still muted by the default mute set. Fails
 * closed: on a readback error it reports the event as still muted. */
bool ukai_obs_muted_paths_events(ukai_obs_client_t *client, uint32_t event_type);

/* The §5 subscription: NOTIFY_EXEC for `exec`; NOTIFY_CREATE, NOTIFY_RENAME,
 * NOTIFY_UNLINK, NOTIFY_LINK, NOTIFY_TRUNCATE, NOTIFY_SETATTRLIST,
 * NOTIFY_SETMODE and NOTIFY_CLOSE for `fs.write` (CLOSE filtered to
 * `modified` at the handler). */
bool ukai_obs_subscribe(ukai_obs_client_t *client);

/* es_mute_process on this process's own audit token. */
bool ukai_obs_mute_self(ukai_obs_client_t *client);

/* Drains one event from the ring; false when the ring is empty. */
bool ukai_obs_poll(ukai_obs_client_t *client, ukai_obs_event *out);

/* Sticky stream-gap flag: ring overflow, a message older than the custody
 * fields, an unknown event type, or a path too long to carry whole. */
bool ukai_obs_gap(const ukai_obs_client_t *client);

/* es_sync_client + semaphore with a wall timeout. */
bool ukai_obs_drain(ukai_obs_client_t *client, uint32_t timeout_ms);

bool ukai_obs_delete(ukai_obs_client_t *client);

#endif /* UKAI_OBS_SHIM_H */
