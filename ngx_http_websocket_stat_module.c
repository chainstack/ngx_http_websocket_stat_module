#include "ngx_http_websocket_stat_format.h"
#include "ngx_http_websocket_stat_frame_counter.h"
#include <assert.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>


typedef struct {
    ngx_flag_t  enable;
    compiled_template *template;
} ngx_http_websocket_stat_srv_conf_t;

typedef struct {
    time_t ws_conn_start_time;
    ngx_frame_counter_t frame_counter;
    ngx_str_t connection_id;

} ngx_http_websocket_stat_ctx;

typedef struct {
    int from_client;
    ngx_http_websocket_stat_ctx *ws_ctx;

} template_ctx_s;


#define UID_LENGTH 32
#define KEY_SIZE 24
#define ACCEPT_SIZE 28
#define GUID_SIZE 36
// It contains 36 characters.
char const *const kWsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
char const *const kWsKey = "Sec-WebSocket-Key";

static char *ngx_http_ws_log_format(ngx_conf_t *cf, ngx_command_t *cmd,
                                    void *conf);
static ngx_int_t ngx_http_websocket_stat_init(ngx_conf_t *cf);

static void *ngx_http_websocket_stat_create_main_conf(ngx_conf_t *cf);
const char *get_core_var(ngx_http_request_t *r, const char *variable);

static ngx_atomic_t *ngx_websocket_stat_active;

compiled_template *log_template;
compiled_template *log_close_template;
compiled_template *log_open_template;

ssize_t (*orig_recv)(ngx_connection_t *c, u_char *buf, size_t size);

char CARET_RETURN = '\n';
ngx_log_t *ws_log = NULL;
const char *UNKNOWN_VAR = "???";

static ngx_command_t ngx_http_websocket_stat_commands[] = {

    {ngx_string("ws_log"), 
     NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_flag_slot, 
     NGX_HTTP_SRV_CONF_OFFSET, 
     offsetof(ngx_http_websocket_conf_t, enable),
     NULL},
    {ngx_string("ws_log_format"), 
     NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_http_ws_log_format, 
     NGX_HTTP_SRV_CONF_OFFSET, 
     offsetof(ngx_http_websocket_conf_t, template), 
     NULL},
    ngx_null_command /* command termination */
};

/* The module context. */
static ngx_http_module_t ngx_http_websocket_stat_module_ctx = {
    NULL,                         /* preconfiguration */
    ngx_http_websocket_stat_init, /* postconfiguration */

    NULL, /* create main configuration */
    NULL,                                     /* init main configuration */

    ngx_http_websocket_stat_create_srv_conf, /* create server configuration */
    ngx_http_websocket_stat_merge_srv_conf, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

/* Module definition. */
ngx_module_t ngx_http_websocket_stat_module = {
    NGX_MODULE_V1,
    &ngx_http_websocket_stat_module_ctx, /* module context */
    ngx_http_websocket_stat_commands,    /* module directives */
    NGX_HTTP_MODULE,                     /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    NULL,                                /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING};

static ngx_http_output_body_filter_pt ngx_http_next_body_filter;
static ngx_http_output_header_filter_pt ngx_http_next_header_filter;


static u_char responce_template[] =
    "WebSocket connections: %lu\n"
    "client websocket frames  | client websocket payload | client tcp data\n"
    "%lu %lu %lu\n"
    "upstream websocket frames  | upstream websocket payload | upstream tcp "
    "data\n"
    "%lu %lu %lu\n";

u_char msg[sizeof(responce_template) + 6 * NGX_ATOMIC_T_LEN];

typedef ssize_t (*send_func)(ngx_connection_t *c, u_char *buf, size_t size);
send_func orig_recv, orig_send;

void
ws_do_log(compiled_template *template, ngx_http_request_t *r, void *ctx)
{
    if (!ws_log) return;
    
    char *log_line = apply_template(template, r, ctx);
    ngx_write_fd(ws_log->file->fd, str, strlen(str));
    ngx_write_fd(ws_log->file->fd, &CARET_RETURN, sizeof(char));
    free(log_line);
}

// Packets that being send to a client
ssize_t
my_send(ngx_connection_t *c, u_char *buf, size_t size)
{
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "SEND START");

    srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_websocket_stat_module);
    if (!srv_conf->enabled) {
        return orig_send(c, buf, size);
    }

    ngx_http_websocket_stat_ctx *ctx;
    ssize_t sz = size;
    u_char *buffer = buf;
    ngx_http_request_t *r = c->data;

    ctx = ngx_http_get_module_ctx(r, ngx_http_websocket_stat_module);
    template_ctx_s template_ctx;
    template_ctx.from_client = 0;
    template_ctx.ws_ctx = ctx;
    while (sz > 0) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "PROCESS SEND FRAME");
        if (frame_counter_process_message(&buffer, &sz,
                                          &(ctx->frame_counter))) {
            ws_do_log(srv_conf->template, r, &template_ctx);
        }
    }
    int n = orig_send(c, buf, size);
    if (n < 0) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "PROCESS SEND RESP FRAME");
        if(!ngx_atomic_cmp_set(ngx_websocket_stat_active, 0, 0)){
          ngx_atomic_fetch_add(ngx_websocket_stat_active, -1);
          ws_do_log(log_close_template, r, &template_ctx);
        }
    }
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "SEND END");
    return n;
}

// Packets received from a client
ssize_t
my_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "RECV START");

    int n = orig_recv(c, buf, size);
    if (n <= 0) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "NO RESPONCE");
        return n;
    }

    ngx_http_websocket_stat_ctx *ctx;
    ssize_t sz = n;
    ngx_http_request_t *r = c->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_websocket_stat_module);
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "INC COUNTER");
    template_ctx_s template_ctx;
    template_ctx.from_client = 1;
    template_ctx.ws_ctx = ctx;
    while (sz > 0) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "PROCESS RECV FRAME");
        if (frame_counter_process_message(&buf, &sz, &ctx->frame_counter)) {

            ws_do_log(log_template, r, &template_ctx);
        }
    }

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "END RECV");

    return n;
}

static ngx_int_t
ngx_http_websocket_stat_header_filter(ngx_http_request_t *r)
{
    return ngx_http_next_header_filter(r);
}

static ngx_int_t
ngx_http_websocket_stat_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_websocket_stat_module);

    if (!srv_conf->enabled) return ngx_http_next_body_filter(r, in);

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "START BODY FILTER");
    if (!r->upstream) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "NO UPSTREAM");
        return ngx_http_next_body_filter(r, in);
    }

    ngx_http_websocket_stat_ctx *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_websocket_stat_module);
    template_ctx_s template_ctx;
    template_ctx.ws_ctx = ctx;

    if (r->headers_in.upgrade) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "UPGRADE FLAG FOUND");
        if (r->upstream->peer.connection) {
            // connection opened
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "PEER.CONNECTION OPENED");
            ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_websocket_stat_ctx));
            if (ctx == NULL) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "NO CONTEXT");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            const char *request_id_str = get_core_var(r, "request_id");
            ctx->connection_id.data = ngx_pcalloc(r->pool, UID_LENGTH + 1);
            ctx->connection_id.len = UID_LENGTH;
            memcpy(ctx->connection_id.data, request_id_str, UID_LENGTH + 1);
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "WS IS OPENED");
            ws_do_log(log_open_template, r, &template_ctx);
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "WS IS OPENED LOGGED");
            ngx_http_set_ctx(r, ctx, ngx_http_websocket_stat_module);
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "CONTEXT IS SET");
            orig_recv = r->connection->recv;
            r->connection->recv = my_recv;
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "PATCHED RECV");
            
            orig_send = r->connection->send;
            r->connection->send = my_send;
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "PATCHED SEND");

            ngx_atomic_fetch_add(ngx_websocket_stat_active, 1);
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "CONN COUNTED");
            ctx->ws_conn_start_time = ngx_time();
        } else {
          if(!ngx_atomic_cmp_set(ngx_websocket_stat_active, 0, 0)){
              ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "WS IS CLOSED");
              ngx_atomic_fetch_add(ngx_websocket_stat_active, -1);
              ws_do_log(log_close_template, r, &template_ctx);
            }
        }
    }
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "END BODY FILTER");

    return ngx_http_next_body_filter(r, in);
}

char buff[100];

const char *
ws_packet_type(ngx_http_request_t *r, void *data)
{
    template_ctx_s *ctx = data;
    ngx_frame_counter_t *frame_cntr = &(ctx->ws_ctx->frame_counter);
    if (!ctx || !frame_cntr)
        return UNKNOWN_VAR;
    sprintf(buff, "%d", frame_cntr->current_frame_type);
    return buff;
}

const char *
ws_packet_size(ngx_http_request_t *r, void *data)
{
    template_ctx_s *ctx = data;
    ngx_frame_counter_t *frame_cntr = &ctx->ws_ctx->frame_counter;
    if (!ctx || !frame_cntr)
        return UNKNOWN_VAR;
    sprintf(buff, "%lu", frame_cntr->current_payload_size);
    return (char *)buff;
}

const char *
ws_packet_source(ngx_http_request_t *r, void *data)
{
    template_ctx_s *ctx = data;
    if (!ctx)
        return UNKNOWN_VAR;
    if (ctx->from_client)
        return "client";
    return "upstream";
}

const char *
get_core_var(ngx_http_request_t *r, const char *variable)
{
    ngx_int_t key = 0;
    ngx_http_variable_value_t *vv;
    ngx_str_t var;
    var.data = (u_char *)variable;
    var.len = strlen(variable);
    while (*variable != '\0')
        key = ngx_hash(key, *(variable++));

    vv = ngx_http_get_variable(r, &var, key);
    memcpy(buff, vv->data, vv->len);
    buff[vv->len] = '\0';
    return buff;
}

const char *
ws_connection_age(ngx_http_request_t *r, void *data)
{
    template_ctx_s *ctx = data;
    if (!ctx || !ctx->ws_ctx)
        return UNKNOWN_VAR;
    sprintf(buff, "%lu", ngx_time() - ctx->ws_ctx->ws_conn_start_time);

    return (char *)buff;
}

const char *
local_time(ngx_http_request_t *r, void *data)
{
    return memcpy(buff, ngx_cached_http_time.data, ngx_cached_http_time.len);
}

const char *
remote_ip(ngx_http_request_t *r, void *data)
{
    memcpy(buff, r->connection->addr_text.data, r->connection->addr_text.len);
    buff[r->connection->addr_text.len] = '\0';

    return buff;
}

const char *
request_id(ngx_http_request_t *r, void *data)
{
    template_ctx_s *ctx = data;
    if (!ctx || !ctx->ws_ctx)
        return UNKNOWN_VAR;
    return (const char *)ctx->ws_ctx->connection_id.data;
}

const char *
upstream_addr(ngx_http_request_t *r, void *data)
{
    template_ctx_s *ctx = data;
    if (!ctx || !ctx->ws_ctx)
        return UNKNOWN_VAR;
    if (r->upstream_states == NULL || r->upstream_states->nelts == 0)
        return UNKNOWN_VAR;
    ngx_http_upstream_state_t *state;
    state = r->upstream_states->elts;
    return (const char *)state->peer->data;
}

#define GEN_CORE_GET_FUNC(fname, var)                                          \
    const char *fname(ngx_http_request_t *r, void *data)                       \
    {                                                                          \
        return get_core_var(r, var);                                           \
    }

GEN_CORE_GET_FUNC(request, "request")
GEN_CORE_GET_FUNC(uri, "uri")
GEN_CORE_GET_FUNC(remote_user, "remote_user")
GEN_CORE_GET_FUNC(remote_addr, "remote_addr")
GEN_CORE_GET_FUNC(remote_port, "remote_port")
GEN_CORE_GET_FUNC(server_addr, "server_addr")
GEN_CORE_GET_FUNC(server_port, "server_port")

const template_variable variables[] = {
    {VAR_NAME("$ws_opcode"), sizeof("ping") - 1, ws_packet_type},
    {VAR_NAME("$ws_payload_size"), NGX_SIZE_T_LEN, ws_packet_size},
    {VAR_NAME("$ws_packet_source"), sizeof("upstream") - 1, ws_packet_source},
    {VAR_NAME("$ws_conn_age"), NGX_SIZE_T_LEN, ws_connection_age},
    {VAR_NAME("$time_local"), sizeof("Mon, 23 Oct 2017 11:27:42 GMT") - 1,
     local_time},
    {VAR_NAME("$upstream_addr"), 60, upstream_addr},
    {VAR_NAME("$request"), 60, request},
    {VAR_NAME("$uri"), 60, uri},
    {VAR_NAME("$request_id"), UID_LENGTH, request_id},
    {VAR_NAME("$remote_user"), 60, remote_user},
    {VAR_NAME("$remote_addr"), 60, remote_addr},
    {VAR_NAME("$remote_port"), 60, remote_port},
    {VAR_NAME("$server_addr"), 60, server_addr},
    {VAR_NAME("$server_port"), 60, server_port},
    // TODO: Delete this since its duplicating $remote_add
    {VAR_NAME("$remote_ip"), sizeof("000.000.000.000") - 1, remote_ip},
    {NULL, 0, 0, NULL}};

static char *
ngx_http_ws_log_format(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_websocket_stat_srv_conf_t  *srv_conf;

    srv_conf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_websocket_stat_module);

    if (!srv_conf->enabled) {
        return NGX_CONF_OK;
    }
 
    ngx_str_t *args = cf->args->elts;
    if (cf->args->nelts == 2) {
        srv_conf->template = compile_template((char *)args[1].data, variables, cf->pool);
        return NGX_CONF_OK;
    }
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Wrong argument number");
    return NGX_CONF_ERROR;
}


static ngx_int_t
ngx_http_websocket_stat_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_websocket_stat_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_websocket_stat_body_filter;

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "INITIALIZED");
    return NGX_OK;
}


static void *
ngx_http_websocket_stat_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_websocket_stat_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_websocket_stat_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;
    conf->template = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_http_websocket_stat_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_websocket_stat_srv_conf_t *prev = parent;
    ngx_http_websocket_stat_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, -1);
    ngx_conf_merge_ptr_value(conf->template, prev->template, NULL);
}