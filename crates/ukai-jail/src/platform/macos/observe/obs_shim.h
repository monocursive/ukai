/* ES observation only: fixed, preallocated records; no custody authority. */
#ifndef UKAI_OBS_SHIM_H
#define UKAI_OBS_SHIM_H
#include <EndpointSecurity/EndpointSecurity.h>
#include <stdbool.h>
#include <stdint.h>
// Two paths per slot: keep the preallocated ring below the 4 MiB evidence budget.
#define UKAI_OBS_RING_CAPACITY 1024u
#define UKAI_OBS_PATH_MAX 1024u
#define UKAI_OBS_TOKEN_WORDS 8
#define UKAI_OBS_HELPERS_MAX 16u

enum {
    UKAI_OBS_EXEC = 1, UKAI_OBS_CREATE = 2, UKAI_OBS_WRITE = 3,
    UKAI_OBS_RENAME = 4, UKAI_OBS_UNLINK = 5, UKAI_OBS_TRUNCATE = 6,
    UKAI_OBS_SETATTRLIST = 7, UKAI_OBS_SETMODE = 8, UKAI_OBS_LINK = 9,
    UKAI_OBS_CLOSE_UNMODIFIED = 10, UKAI_OBS_CREATE_DENIED = 11,
};
typedef struct ukai_obs_client ukai_obs_client_t;
typedef struct {
    int32_t type;
    uint32_t event_type; /* real ES type: seq_num is per type, not per action */
    uint64_t global_seq;
    uint64_t seq;
    uint32_t token[UKAI_OBS_TOKEN_WORDS];
    int32_t modified;
    int32_t ignored;
    uint16_t path_len;
    uint16_t path2_len;
    uint8_t path[UKAI_OBS_PATH_MAX]; /* source for rename/link */
    uint8_t path2[UKAI_OBS_PATH_MAX]; /* destination for rename/link */
} ukai_obs_event;
int32_t ukai_obs_new_descendants(ukai_obs_client_t **out);
bool ukai_obs_unmute_all(ukai_obs_client_t *client);
bool ukai_obs_muted_paths_events(ukai_obs_client_t *client, uint32_t event_type);
bool ukai_obs_verify_unmuted(ukai_obs_client_t *client);
bool ukai_obs_subscribe(ukai_obs_client_t *client);
bool ukai_obs_mute_self(ukai_obs_client_t *client);
/* Exact-token exclusion, installed before subscribing. Unlike ES process
 * muting it cannot suppress the launcher's new exec image or instigated child. */
bool ukai_obs_exclude_token(ukai_obs_client_t *client, const uint32_t token[8]);
bool ukai_obs_poll(ukai_obs_client_t *client, ukai_obs_event *out);
bool ukai_obs_gap(const ukai_obs_client_t *client);
bool ukai_obs_invalid(const ukai_obs_client_t *client);
uint64_t ukai_obs_dropped(const ukai_obs_client_t *client);
bool ukai_obs_drain(ukai_obs_client_t *client, uint32_t timeout_ms);
bool ukai_obs_delete(ukai_obs_client_t *client);
#endif
