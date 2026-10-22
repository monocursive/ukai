/*
 * EndpointSecurity custody shim (jail-macos §4.1, §4.3, §4.5).
 *
 * Fixed-size API only: after client creation the shim allocates nothing,
 * opens nothing and forks nothing (§4.1 rule 4). Events cross to Rust as
 * fixed 64-byte records drained from a preallocated ring; the handler never
 * reads a path, argument, environment or any other variable-length field
 * the workload controls (§4.1 rule 3).
 */
#ifndef UKAI_ES_SHIM_H
#define UKAI_ES_SHIM_H

#include <EndpointSecurity/EndpointSecurity.h>
#include <stdbool.h>
#include <stdint.h>

#define UKAI_ES_RING_CAPACITY 65536u
#define UKAI_ES_TOKEN_WORDS 8

/* Shim-internal event type numbers; the custody notify set of §4.1 rule 3. */
enum {
    UKAI_ES_EVENT_FORK = 1,
    UKAI_ES_EVENT_EXEC = 2,
    UKAI_ES_EVENT_EXIT = 3,
};

typedef struct ukai_es_client ukai_es_client_t;

/* Exactly 64 bytes, all fields fixed-size (§4.1 rule 3). */
typedef struct {
    int32_t type;
    uint64_t global_seq;
    uint64_t seq;
    uint32_t token[UKAI_ES_TOKEN_WORDS];
    int32_t exit_status;
} ukai_es_event;

/* Creates a descendants client and its preallocated ring. Allocates its
 * last memory here; nothing below allocates. Returns the raw
 * es_new_client_result_t so Rust can map the result codes. */
int32_t ukai_es_new_descendants(ukai_es_client_t **out);

/* es_unmute_all_paths + es_unmute_all_target_paths (§4.3 step 1). */
bool ukai_es_unmute_all(ukai_es_client_t *client);

/* Whether `event_type` is still muted by the default mute set (§4.3 step 1:
 * refuse the client if any custody event stays muted). Fails closed: on a
 * readback error it reports the event as still muted. Allocates inside the
 * ES framework to answer, so it belongs to client creation only. */
bool ukai_es_muted_paths_events(ukai_es_client_t *client, uint32_t event_type);

/* Subscribes NOTIFY_FORK, NOTIFY_EXEC, NOTIFY_EXIT — nothing else. */
bool ukai_es_subscribe_custody(ukai_es_client_t *client);

/* The guard subscription (§4.5 step 1): AUTH_SIGNAL,
 * AUTH_PROC_SUSPEND_RESUME and AUTH_EXEC; sets and reads back
 * ES_DEADLINE_MISS_MODE_FAIL_CLOSED (fail-closed denies a late answer and
 * never kills the client). Its callback denies every request inline, never
 * caches a result, counts denials atomically and never kills the client. */
bool ukai_es_subscribe_guard(ukai_es_client_t *client);

/* es_mute_process on the custodian's own audit token (§4.3 step 3). */
bool ukai_es_mute_self(ukai_es_client_t *client);

/* Drains one event from the ring; false when the ring is empty. */
bool ukai_es_poll(ukai_es_client_t *client, ukai_es_event *out);

/* Sticky stream-gap flag: set on ring overflow, on a message older than the
 * custody fields (the prototype's m->version < 4 rule) and on an event type
 * a custody client must never see. The poller reads it; the stop machine
 * treats it as `gap` (§4.4, §4.5). */
bool ukai_es_ring_overflowed(ukai_es_client_t *client);

/* es_sync_client + semaphore with a wall timeout. */
bool ukai_es_drain(ukai_es_client_t *client, uint32_t timeout_ms);

/* Denials counted by the guard callback since client creation. */
uint64_t ukai_es_guard_denials(const ukai_es_client_t *client);

/* proc_signal_with_audittoken; returns errno. Never kill(2) (§4.1 rule 5). */
int32_t ukai_es_signal(const uint32_t token[UKAI_ES_TOKEN_WORDS], int32_t sig);

/* task_info(TASK_AUDIT_TOKEN) of this process. */
bool ukai_es_self_token(uint32_t out[UKAI_ES_TOKEN_WORDS]);

/* mach_continuous_time: counts sleep (§4.3 step 6, wall deadline). */
uint64_t ukai_es_continuous_time(void);

bool ukai_es_delete(ukai_es_client_t *client);

#endif /* UKAI_ES_SHIM_H */
