/* Compile-only inventory of the Endpoint Security APIs used by both shims.
 * No SDK version heuristic: every named function, type and constant must exist.
 * Keep shim compilation separate so implementation bugs remain hard errors. */
#include <EndpointSecurity/EndpointSecurity.h>

void ukai_es_sdk_probe(void) {
    (void)&es_delete_client;
    (void)&es_get_deadline_miss_mode;
    (void)&es_mute_process;
    (void)&es_muted_paths_events;
    (void)&es_new_descendants_client;
    (void)&es_release_muted_paths;
    (void)&es_respond_auth_result;
    (void)&es_set_deadline_miss_mode;
    (void)&es_subscribe;
    (void)&es_sync_client;
    (void)&es_unmute_all_paths;
    (void)&es_unmute_all_target_paths;
    (void)sizeof(es_client_t *);
    (void)sizeof(es_deadline_miss_mode_t *);
    (void)sizeof(es_event_type_t *);
    (void)sizeof(es_file_t *);
    (void)sizeof(es_message_t *);
    (void)sizeof(es_muted_path_t *);
    (void)sizeof(es_muted_paths_t *);
    (void)sizeof(es_new_client_result_t *);
    (void)sizeof(es_process_t *);
    (void)sizeof(es_string_token_t *);
    (void)ES_AUTH_RESULT_DENY;
    (void)ES_DEADLINE_MISS_MODE_FAIL_CLOSED;
    (void)ES_DEADLINE_MISS_MODE_KILL;
    (void)ES_DESTINATION_TYPE_EXISTING_FILE;
    (void)ES_DESTINATION_TYPE_NEW_PATH;
    (void)ES_EVENT_TYPE_AUTH_EXEC;
    (void)ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME;
    (void)ES_EVENT_TYPE_AUTH_SIGNAL;
    (void)ES_EVENT_TYPE_NOTIFY_CLOSE;
    (void)ES_EVENT_TYPE_NOTIFY_CREATE;
    (void)ES_EVENT_TYPE_NOTIFY_EXEC;
    (void)ES_EVENT_TYPE_NOTIFY_EXIT;
    (void)ES_EVENT_TYPE_NOTIFY_FORK;
    (void)ES_EVENT_TYPE_NOTIFY_LINK;
    (void)ES_EVENT_TYPE_NOTIFY_RENAME;
    (void)ES_EVENT_TYPE_NOTIFY_SETATTRLIST;
    (void)ES_EVENT_TYPE_NOTIFY_SETMODE;
    (void)ES_EVENT_TYPE_NOTIFY_TRUNCATE;
    (void)ES_EVENT_TYPE_NOTIFY_UNLINK;
    (void)ES_NEW_CLIENT_RESULT_ERR_INTERNAL;
    (void)ES_NEW_CLIENT_RESULT_SUCCESS;
    (void)ES_RETURN_SUCCESS;
}
