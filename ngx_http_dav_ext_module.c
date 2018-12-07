
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <expat.h>


#define NGX_HTTP_DAV_EXT_OFF                      2

#define NGX_HTTP_DAV_EXT_PREALLOCATE              50

#define NGX_HTTP_DAV_EXT_NODE_PROPFIND            0x01
#define NGX_HTTP_DAV_EXT_NODE_PROP                0x02
#define NGX_HTTP_DAV_EXT_NODE_PROPNAME            0x04
#define NGX_HTTP_DAV_EXT_NODE_ALLPROP             0x08

#define NGX_HTTP_DAV_EXT_PROP_DISPLAYNAME         0x01
#define NGX_HTTP_DAV_EXT_PROP_GETCONTENTLENGTH    0x02
#define NGX_HTTP_DAV_EXT_PROP_GETLASTMODIFIED     0x04
#define NGX_HTTP_DAV_EXT_PROP_RESOURCETYPE        0x08
#define NGX_HTTP_DAV_EXT_PROP_LOCKDISCOVERY       0x10
#define NGX_HTTP_DAV_EXT_PROP_SUPPORTEDLOCK       0x20

#define NGX_HTTP_DAV_EXT_PROP_ALL                 0x7f
#define NGX_HTTP_DAV_EXT_PROP_NAMES               0x80


typedef struct {
    ngx_str_t                    uri;
    ngx_str_t                    name;
    ngx_str_t                    lock_root;

    time_t                       mtime;
    time_t                       lock_timeout;

    off_t                        size;
    uint32_t                     lock_token;

    unsigned                     dir:1;
    unsigned                     lock_supported:1;
    ngx_uint_t                   lock_depth;
} ngx_http_dav_ext_entry_t;


typedef struct {
    ngx_uint_t                   nodes;
    ngx_uint_t                   props;
} ngx_http_dav_ext_ctx_t;


typedef struct {
    ngx_uint_t                   methods;
    ngx_shm_zone_t              *shm_zone;
} ngx_http_dav_ext_loc_conf_t;


typedef struct {
    ngx_queue_t                  queue;
    uint32_t                     token;
    time_t                       expire;
    size_t                       len;
    ngx_uint_t                   infinite;
    u_char                       data[1];
} ngx_http_dav_ext_node_t;


typedef struct {
    ngx_queue_t                  queue;
} ngx_http_dav_ext_lock_sh_t;


typedef struct {
    time_t                       timeout;
    ngx_slab_pool_t             *shpool;
    ngx_http_dav_ext_lock_sh_t  *sh;
} ngx_http_dav_ext_lock_t;


static ngx_int_t ngx_http_dav_ext_precontent_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_ext_content_handler(ngx_http_request_t *r);
static void ngx_http_dav_ext_propfind_handler(ngx_http_request_t *r);
static void ngx_http_dav_ext_start_xml_elt(void *user_data,
    const XML_Char *name, const XML_Char **atts);
static void ngx_http_dav_ext_end_xml_elt(void *user_data, const XML_Char *name);
static int ngx_http_dav_ext_xmlcmp(const char *xname, const char *sname);
static ngx_int_t ngx_http_dav_ext_propfind(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_ext_depth(ngx_http_request_t *r);
static uint32_t ngx_http_dav_ext_token(ngx_http_request_t *r, ngx_str_t *name);
static uintptr_t ngx_http_dav_ext_format_token(u_char *dst, uint32_t token,
    ngx_uint_t brackets);
static ngx_int_t ngx_http_dav_ext_propfind_send_response(ngx_http_request_t *r,
    ngx_array_t *entries);
static uintptr_t ngx_http_dav_ext_format_response(ngx_http_request_t *r,
    u_char *dst, ngx_http_dav_ext_entry_t *entry);
static uintptr_t ngx_http_dav_ext_format_lockdiscovery(ngx_http_request_t *r,
    u_char *dst, ngx_http_dav_ext_entry_t *entry);
static ngx_int_t ngx_http_dav_ext_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);
static ngx_int_t ngx_http_dav_ext_verify_lock(ngx_http_request_t *r,
    ngx_str_t *uri);
static ngx_int_t ngx_http_dav_ext_lock_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_ext_unlock_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_ext_lock_response(ngx_http_request_t *r,
    ngx_uint_t status, time_t timeout, ngx_uint_t depth, uint32_t token);
static void *ngx_http_dav_ext_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_dav_ext_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_dav_ext_lock_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_dav_ext_lock(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_dav_ext_init(ngx_conf_t *cf);


static ngx_conf_bitmask_t  ngx_http_dav_ext_methods_mask[] = {
    { ngx_string("off"),      NGX_HTTP_DAV_EXT_OFF },
    { ngx_string("propfind"), NGX_HTTP_PROPFIND    },
    { ngx_string("options"),  NGX_HTTP_OPTIONS     },
    { ngx_string("lock"),     NGX_HTTP_LOCK        },
    { ngx_string("unlock"),   NGX_HTTP_UNLOCK      },
    { ngx_null_string,        0                    }
};


static ngx_command_t  ngx_http_dav_ext_commands[] = {

    { ngx_string("dav_ext_methods"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_dav_ext_loc_conf_t, methods),
      &ngx_http_dav_ext_methods_mask },

    { ngx_string("dav_ext_lock_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE12,
      ngx_http_dav_ext_lock_zone,
      0,
      0,
      NULL },

    { ngx_string("dav_ext_lock"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_dav_ext_lock,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_dav_ext_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_dav_ext_init,                 /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_dav_ext_create_loc_conf,      /* create location configuration */
    ngx_http_dav_ext_merge_loc_conf,       /* merge location configuration */
};


ngx_module_t  ngx_http_dav_ext_module = {
    NGX_MODULE_V1,
    &ngx_http_dav_ext_module_ctx,          /* module context */
    ngx_http_dav_ext_commands,             /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_dav_ext_precontent_handler(ngx_http_request_t *r)
{
    size_t                        len;
    u_char                       *p, *last, *host;
    ngx_str_t                     uri;
    ngx_int_t                     rc;
    ngx_table_elt_t              *dest;
    ngx_http_dav_ext_loc_conf_t  *dlcf;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_ext_module);

    if (dlcf->shm_zone == NULL) {
        return NGX_DECLINED;
    }

    if (r->method & (NGX_HTTP_PUT|NGX_HTTP_DELETE|NGX_HTTP_MKCOL|NGX_HTTP_MOVE))
    {
        rc = ngx_http_dav_ext_verify_lock(r, &r->uri);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    if (r->method & (NGX_HTTP_MOVE|NGX_HTTP_COPY)) {
        dest = r->headers_in.destination;
        if (dest == NULL) {
            return NGX_DECLINED;
        }

        p = dest->value.data;

        if (p[0] == '/') {
            last = p + dest->value.len;
            goto destination_done;
        }

        len = r->headers_in.server.len;

        if (len == 0) {
            return NGX_DECLINED;
        }

#if (NGX_HTTP_SSL)

        if (r->connection->ssl) {
            if (ngx_strncmp(dest->value.data, "https://", sizeof("https://") - 1)
                != 0)
            {
                return NGX_DECLINED;
            }

            host = dest->value.data + sizeof("https://") - 1;

        } else
#endif
        {
            if (ngx_strncmp(dest->value.data, "http://", sizeof("http://") - 1)
                != 0)
            {
                return NGX_DECLINED;
            }

            host = dest->value.data + sizeof("http://") - 1;
        }

        if (ngx_strncmp(host, r->headers_in.server.data, len) != 0) {
            return NGX_DECLINED;
        }

        last = dest->value.data + dest->value.len;

        for (p = host + len; p < last; p++) {
            if (*p == '/') {
                goto destination_done;
            }
        }

        return NGX_DECLINED;

destination_done:

        uri.data = p;
        uri.len = last - p;

        rc = ngx_http_dav_ext_verify_lock(r, &uri);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_dav_ext_content_handler(ngx_http_request_t *r)
{
    ngx_int_t                     rc;
    ngx_table_elt_t              *h;
    ngx_http_dav_ext_loc_conf_t  *dlcf;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_ext_module);

    if (!(r->method & dlcf->methods)) {
        return NGX_DECLINED;
    }

    switch (r->method) {

    case NGX_HTTP_PROPFIND:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http dav_ext propfind");

        rc = ngx_http_read_client_request_body(r,
                                            ngx_http_dav_ext_propfind_handler);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        return NGX_DONE;

    case NGX_HTTP_OPTIONS:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http dav_ext options");

        rc = ngx_http_discard_request_body(r);

        if (rc != NGX_OK) {
            return rc;
        }

        h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_str_set(&h->key, "DAV");
        h->value.len = 1;
        h->value.data = (u_char *) (dlcf->shm_zone ? "2" : "1");
        h->hash = 1;

        h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* XXX */
        ngx_str_set(&h->key, "Allow");
        ngx_str_set(&h->value,
           "GET,HEAD,PUT,DELETE,MKCOL,COPY,MOVE,PROPFIND,OPTIONS,LOCK,UNLOCK");
        h->hash = 1;

        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = 0;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }

        return ngx_http_send_special(r, NGX_HTTP_LAST);

    case NGX_HTTP_LOCK:

        if (dlcf->shm_zone == NULL) {
            return NGX_HTTP_NOT_ALLOWED;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http dav_ext lock");

        /*
         * Body is expected to have lock type, but since we
         * only support write/exclusive locks, we ignore it.
         * Ideally we could produce an error if a lock of
         * another type is requested, but the amount of work
         * required for that is not worth it.
         */

        rc = ngx_http_discard_request_body(r);

        if (rc != NGX_OK) {
            return rc;
        }

        return ngx_http_dav_ext_lock_handler(r);

    case NGX_HTTP_UNLOCK:

        if (dlcf->shm_zone == NULL) {
            return NGX_HTTP_NOT_ALLOWED;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http dav_ext unlock");

        rc = ngx_http_discard_request_body(r);

        if (rc != NGX_OK) {
            return rc;
        }

        return ngx_http_dav_ext_unlock_handler(r);
    }

    return NGX_DECLINED;
}


static void
ngx_http_dav_ext_propfind_handler(ngx_http_request_t *r)
{
    off_t                    len;
    ngx_buf_t               *b;
    XML_Parser               parser;
    ngx_chain_t             *cl;
    ngx_http_dav_ext_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dav_ext propfind handler");

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dav_ext_ctx_t));
    if (ctx == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_dav_ext_module);

    parser = XML_ParserCreate(NULL);
    if (parser == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "XML_ParserCreate() failed");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    XML_SetUserData(parser, ctx);

    XML_SetElementHandler(parser, ngx_http_dav_ext_start_xml_elt,
                          ngx_http_dav_ext_end_xml_elt);

    len = 0;

    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        b = cl->buf;

        if (b->in_file) {
            XML_ParserFree(parser);

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "PROPFIND client body is in file, "
                          "you may want to increase client_body_buffer_size");

            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (ngx_buf_special(b)) {
            continue;
        }

        len += b->last - b->pos;

        if (!XML_Parse(parser, (const char*) b->pos, b->last - b->pos,
                       b->last_buf))
        {
            XML_ParserFree(parser);

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "XML_Parse() failed");

            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    XML_ParserFree(parser);

    if (len == 0) {
        /*
         * For easier debugging treat bodiless requests
         * as if they expect all properties.
         */

        ctx->props = NGX_HTTP_DAV_EXT_PROP_ALL;
    }

    ngx_http_finalize_request(r, ngx_http_dav_ext_propfind(r));
}


static void
ngx_http_dav_ext_start_xml_elt(void *user_data, const XML_Char *name,
    const XML_Char **atts)
{
    ngx_http_dav_ext_ctx_t *ctx = user_data;

    if (ngx_http_dav_ext_xmlcmp(name, "propfind") == 0) {
        ctx->nodes ^= NGX_HTTP_DAV_EXT_NODE_PROPFIND;
    }

    if (ngx_http_dav_ext_xmlcmp(name, "prop") == 0) {
        ctx->nodes ^= NGX_HTTP_DAV_EXT_NODE_PROP;
    }

    if (ngx_http_dav_ext_xmlcmp(name, "propname") == 0) {
        ctx->nodes ^= NGX_HTTP_DAV_EXT_NODE_PROPNAME;
    }

    if (ngx_http_dav_ext_xmlcmp(name, "allprop") == 0) {
        ctx->nodes ^= NGX_HTTP_DAV_EXT_NODE_ALLPROP;
    }
}


static void
ngx_http_dav_ext_end_xml_elt(void *user_data, const XML_Char *name)
{
    ngx_http_dav_ext_ctx_t *ctx = user_data;

    if (ctx->nodes & NGX_HTTP_DAV_EXT_NODE_PROPFIND) {

        if (ctx->nodes & NGX_HTTP_DAV_EXT_NODE_PROP) {
            if (ngx_http_dav_ext_xmlcmp(name, "displayname") == 0) {
                ctx->props |= NGX_HTTP_DAV_EXT_PROP_DISPLAYNAME;
            }

            if (ngx_http_dav_ext_xmlcmp(name, "getcontentlength") == 0) {
                ctx->props |= NGX_HTTP_DAV_EXT_PROP_GETCONTENTLENGTH;
            }

            if (ngx_http_dav_ext_xmlcmp(name, "getlastmodified") == 0) {
                ctx->props |= NGX_HTTP_DAV_EXT_PROP_GETLASTMODIFIED;
            }

            if (ngx_http_dav_ext_xmlcmp(name, "resourcetype") == 0) {
                ctx->props |= NGX_HTTP_DAV_EXT_PROP_RESOURCETYPE;
            }

            if (ngx_http_dav_ext_xmlcmp(name, "lockdiscovery") == 0) {
                ctx->props |= NGX_HTTP_DAV_EXT_PROP_LOCKDISCOVERY;
            }

            if (ngx_http_dav_ext_xmlcmp(name, "supportedlock") == 0) {
                ctx->props |= NGX_HTTP_DAV_EXT_PROP_SUPPORTEDLOCK;
            }
        }

        if (ctx->nodes & NGX_HTTP_DAV_EXT_NODE_PROPNAME) {
            ctx->props |= NGX_HTTP_DAV_EXT_PROP_NAMES;
        }

        if (ctx->nodes & NGX_HTTP_DAV_EXT_NODE_ALLPROP) {
            ctx->props = NGX_HTTP_DAV_EXT_PROP_ALL;
        }
    }

    ngx_http_dav_ext_start_xml_elt(user_data, name, NULL);
}


static int
ngx_http_dav_ext_xmlcmp(const char *xname, const char *sname)
{
    char  *c;

    c = strrchr(xname, ':');

    return strcmp(c ? c + 1 : xname, sname);
}


static ngx_int_t
ngx_http_dav_ext_propfind(ngx_http_request_t *r)
{
    size_t                     root, allocated;
    u_char                    *p, *last, *filename;
    uintptr_t                  escape;
    ngx_int_t                  rc;
    ngx_err_t                  err;
    ngx_str_t                  path, name, uri;
    ngx_dir_t                  dir;
    ngx_uint_t                 depth;
    ngx_array_t                entries;
    ngx_file_info_t            fi;
    ngx_http_dav_ext_entry_t  *entry;

    if (ngx_array_init(&entries, r->pool, 40, sizeof(ngx_http_dav_ext_entry_t))
        != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_dav_ext_depth(r);

    if (rc == NGX_ERROR) {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (rc == NGX_MAX_INT_T_VALUE) {

        /*
         * RFC4918 allows us to return 403 error in this case.
         * However we do not return the precondition code.
         *
         * 403 Forbidden -  A server MAY reject PROPFIND requests on
         * collections with depth header of "Infinity", in which case
         * it SHOULD use this error with the precondition code
         * 'propfind-finite-depth' inside the error body.
         */

        return NGX_HTTP_FORBIDDEN;
    }

    depth = rc;

    last = ngx_http_map_uri_to_path(r, &path, &root,
                                    NGX_HTTP_DAV_EXT_PREALLOCATE);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    allocated = path.len;
    path.len = last - path.data;

    if (path.len > 1 && path.data[path.len - 1] == '/') {
        path.len--;

    } else {
        last++;
    }

    path.data[path.len] = '\0';

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dav_ext propfind path: \"%s\"", path.data);

    if (ngx_file_info(path.data, &fi) == NGX_FILE_ERROR) {
        return NGX_HTTP_NOT_FOUND;
    }

    if (r->uri.len < 2) {
        name = r->uri;

    } else {
        name.data = &r->uri.data[r->uri.len - 1];
        name.len = (name.data[0] == '/') ? 0 : 1;

        while (name.data != r->uri.data) {
            p = name.data - 1;
            if (*p == '/') {
                break;
            }

            name.data--;
            name.len++;
        }
    }

    if (r->valid_unparsed_uri) {
        uri = r->unparsed_uri;

    } else {
        escape = 2 * ngx_escape_uri(NULL, r->uri.data, r->uri.len,
                                    NGX_ESCAPE_URI);
        if (escape == 0) {
            uri = r->uri;

        } else {
            uri.data = ngx_pnalloc(r->pool, r->uri.len + escape);
            if (uri.data == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            p = (u_char *) ngx_escape_uri(uri.data, r->uri.data, r->uri.len,
                                          NGX_ESCAPE_URI);
            uri.len = p - uri.data;
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dav_ext propfind name:\"%V\", uri:\"%V\"",
                   &name, &uri);

    entry = ngx_array_push(&entries);
    if (entry == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memzero(entry, sizeof(ngx_http_dav_ext_entry_t));

    /* XXX fill lock-related fields */

    entry->uri = uri;
    entry->name = name;
    entry->dir = ngx_is_dir(&fi);
    entry->mtime = ngx_file_mtime(&fi);
    entry->size = ngx_file_size(&fi);

    if (depth == 0 || !entry->dir) {
        return ngx_http_dav_ext_propfind_send_response(r, &entries);
    }

    if (ngx_open_dir(&path, &dir) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                      ngx_open_dir_n " \"%s\" failed", path.data);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = NGX_OK;

    filename = path.data;
    filename[path.len] = '/';

    for ( ;; ) {
        ngx_set_errno(0);

        if (ngx_read_dir(&dir) == NGX_ERROR) {
            err = ngx_errno;

            if (err != NGX_ENOMOREFILES) {
                ngx_log_error(NGX_LOG_CRIT, r->connection->log, err,
                              ngx_read_dir_n " \"%V\" failed", &path);
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            break;
        }

        name.len = ngx_de_namelen(&dir);
        name.data = ngx_de_name(&dir);

        if (name.data[0] == '.') {
            continue;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http dav_ext propfind child path: \"%s\"", name.data);

        entry = ngx_array_push(&entries);
        if (entry == NULL) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        ngx_memzero(entry, sizeof(ngx_http_dav_ext_entry_t));

        if (!dir.valid_info) {

            if (path.len + 1 + name.len + 1 > allocated) {
                allocated = path.len + 1 + name.len + 1
                            + NGX_HTTP_DAV_EXT_PREALLOCATE;

                filename = ngx_pnalloc(r->pool, allocated);
                if (filename == NULL) {
                    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                    break;
                }

                last = ngx_cpystrn(filename, path.data, path.len + 1);
            }

            ngx_cpystrn(last, name.data, name.len + 1);

            if (ngx_de_info(filename, &dir) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                              ngx_de_info_n " \"%s\" failed", filename);
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                break;
            }
        }

        escape = 2 * ngx_escape_uri(NULL, name.data, name.len,
                                    NGX_ESCAPE_URI_COMPONENT);

        p = ngx_pnalloc(r->pool, uri.len + 1 + name.len + escape + 1);
        if (p == NULL) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        entry->uri.data = p;

        p = ngx_cpymem(p, uri.data, uri.len);

        if (uri.len && uri.data[uri.len - 1] != '/') {
            *p++ = '/';
        }

        p = (u_char *) ngx_escape_uri(p, name.data, name.len,
                                      NGX_ESCAPE_URI_COMPONENT);

        if (ngx_de_is_dir(&dir)) {
            *p++ = '/';
        }

        entry->uri.len = p - entry->uri.data;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http dav_ext propfind child name:\"%V\", uri:\"%V\"",
                       &name, &entry->uri);

        p = ngx_pnalloc(r->pool, name.len);
        if (p == NULL) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        ngx_memcpy(p, name.data, name.len);

        entry->name.data = p;
        entry->name.len = name.len;

        entry->dir = ngx_de_is_dir(&dir);
        entry->mtime = ngx_de_mtime(&dir);
        entry->size = ngx_de_size(&dir);
    }

    if (ngx_close_dir(&dir) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_close_dir_n " \"%V\" failed", &path);
    }

    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_http_dav_ext_propfind_send_response(r, &entries);
}


static ngx_int_t
ngx_http_dav_ext_depth(ngx_http_request_t *r)
{
    ngx_table_elt_t  *depth;

    depth = r->headers_in.depth;

    if (depth == NULL) {
        return 0;
    }

    if (depth->value.len == 1) {

        if (depth->value.data[0] == '0') {
            return 0;
        }

        if (depth->value.data[0] == '1') {
            return 1;
        }

    } else {

        if (depth->value.len == sizeof("infinity") - 1
            && ngx_strcmp(depth->value.data, "infinity") == 0)
        {
            return NGX_MAX_INT_T_VALUE;
        }
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "client sent invalid \"Depth\" header: \"%V\"",
                  &depth->value);

    return NGX_ERROR;
}


static uint32_t
ngx_http_dav_ext_token(ngx_http_request_t *r, ngx_str_t *name)
{
    u_char            ch;
    uint32_t          token;
    ngx_str_t         value;
    ngx_uint_t        i, n;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header;

    part = &r->headers_in.headers.part;

    header = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        for (n = 0; n < name->len && n < header[i].key.len; n++) {
            ch = header[i].key.data[n];

            if (ch >= 'A' && ch <= 'Z') {
                ch |= 0x20;
            }

            if (name->data[n] != ch) {
                break;
            }
        }

        if (n == name->len && n == header[i].key.len) {
            value = header[i].value;

            if (value.len
                && value.data[0] == '('
                && value.data[value.len - 1] == ')')
            {
                value.data++;
                value.len -= 2;
            }

            if (value.len != sizeof("<urn:deadbeef>") - 1) {
                return 0;
            }

            token = 0;

            for (n = 0; n < 8; n++) {
                ch = value.data[5 + n];

                if (ch >= '0' && ch <= '9') {
                    token = token * 16 + (ch - '0');
                    continue;
                }

                ch = (u_char) (ch | 0x20);

                if (ch >= 'a' && ch <= 'f') {
                    token = token * 16 + (ch - 'a' + 10);
                    continue;
                }

                return 0;
            }

            return token;
        }
    }

    return 0;
}


static uintptr_t
ngx_http_dav_ext_format_token(u_char *dst, uint32_t token, ngx_uint_t brackets)
{
    ngx_uint_t  n;

    static u_char  hex[] = "0123456789abcdef";

    if (dst == NULL) {
        return sizeof("<urn:deadbeef>") - 1 + (brackets ? 2 : 0);
    }

    if (brackets) {
        *dst++ = '<';
    }

    dst = ngx_cpymem(dst, "urn:", 4);

    for (n = 0; n < 4; n++) {
        *dst++ = hex[token >> 28];
        *dst++ = hex[(token >> 24) & 0xf];
        token <<= 8;
    }

    if (brackets) {
        *dst++ = '>';
    }

    return (uintptr_t) dst;
}


static ngx_int_t
ngx_http_dav_ext_propfind_send_response(ngx_http_request_t *r,
    ngx_array_t *entries)
{
    size_t                     len;
    ngx_buf_t                 *b;
    ngx_int_t                  rc;
    ngx_uint_t                 n;
    ngx_chain_t                cl;
    ngx_http_dav_ext_entry_t  *entry;

    static u_char head[] = 
        "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n"
        "<D:multistatus xmlns:D=\"DAV:\">\n";

    static u_char tail[] = 
        "</D:multistatus>\n";

    len = sizeof(head) - 1 + sizeof(tail) - 1;

    entry = entries->elts;

    for (n = 0; n < entries->nelts; n++) {
        len += ngx_http_dav_ext_format_response(r, NULL, &entry[n]);
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last = ngx_cpymem(b->last, head, sizeof(head) - 1);

    for (n = 0; n < entries->nelts; n++) {
        b->last = (u_char *) ngx_http_dav_ext_format_response(r, b->last,
                                                              &entry[n]);
    }

    b->last = ngx_cpymem(b->last, tail, sizeof(tail) - 1);

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    cl.buf = b;
    cl.next = NULL;

    r->headers_out.status = 207;
    ngx_str_set(&r->headers_out.status_line, "207 Multi-Status");

    r->headers_out.content_length_n = b->last - b->pos;

    r->headers_out.content_type_len = sizeof("text/xml") - 1;
    ngx_str_set(&r->headers_out.content_type, "text/xml");
    r->headers_out.content_type_lowcase = NULL;

    ngx_str_set(&r->headers_out.charset, "utf-8");

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &cl);
}


static uintptr_t
ngx_http_dav_ext_format_response(ngx_http_request_t *r, u_char *dst,
    ngx_http_dav_ext_entry_t *entry)
{
    size_t                   len;
    ngx_http_dav_ext_ctx_t  *ctx;

    static u_char head[] = 
        "<D:response>\n"
        "<D:href>";

    /* uri */

    static u_char prop[] =
        "</D:href>\n"
        "<D:propstat>\n"
        "<D:prop>\n";

    /* properties */

    static u_char tail[] =
        "</D:prop>\n"
        "<D:status>HTTP/1.1 200 OK</D:status>\n"
        "</D:propstat>\n"
        "</D:response>\n";

    static u_char names[] =
        "<D:displayname/>\n"
        "<D:getcontentlength/>\n"
        "<D:getlastmodified/>\n"
        "<D:resourcetype/>\n"
        "<D:lockdiscovery/>\n"
        "<D:supportedlock/>\n";


    static u_char supportedlock[] =
        "<D:lockentry>\n"
        "<D:lockscope><D:exclusive/></D:lockscope>\n"
        "<D:locktype><D:write/></D:locktype>\n"
        "</D:lockentry>\n";

    ctx = ngx_http_get_module_ctx(r, ngx_http_dav_ext_module);

    if (dst == NULL) {
        len = sizeof(head) - 1
              + sizeof(prop) - 1
              + sizeof(tail) - 1;

        len += entry->uri.len + ngx_escape_html(NULL, entry->uri.data,
                                                entry->uri.len);

        if (ctx->props & NGX_HTTP_DAV_EXT_PROP_NAMES) {
            len += sizeof(names) - 1;

        } else {
            len += sizeof("<D:displayname>"
                          "</D:displayname>\n"

                          "<D:getcontentlength>"
                          "</D:getcontentlength>\n"

                          "<D:getlastmodified>"
                          "Mon, 28 Sep 1970 06:00:00 GMT"
                          "</D:getlastmodified>\n"

                          "<D:resourcetype>"
                          "<D:collection/>"
                          "</D:resourcetype>\n"

                          "<D:supportedlock>\n"
                          "</D:supportedlock>\n") - 1;

            /* displayname */
            len += entry->name.len
                   + ngx_escape_html(NULL, entry->name.data, entry->name.len);

            /* getcontentlength */
            len += NGX_OFF_T_LEN;

            len += ngx_http_dav_ext_format_lockdiscovery(r, NULL, entry);

            /* supportedlock */
            if (entry->lock_supported) {
                len += sizeof(supportedlock) - 1;
            }
        }

        return len;
    }

    dst = ngx_cpymem(dst, head, sizeof(head) - 1);
    dst = (u_char *) ngx_escape_html(dst, entry->uri.data, entry->uri.len);
    dst = ngx_cpymem(dst, prop, sizeof(prop) - 1);

    if (ctx->props & NGX_HTTP_DAV_EXT_PROP_NAMES) {
        dst = ngx_cpymem(dst, names, sizeof(names) - 1);

    } else {
        if (ctx->props & NGX_HTTP_DAV_EXT_PROP_DISPLAYNAME) {
            dst = ngx_cpymem(dst, "<D:displayname>",
                             sizeof("<D:displayname>") - 1);
            dst = (u_char *) ngx_escape_html(dst, entry->name.data,
                                             entry->name.len);
            dst = ngx_cpymem(dst, "</D:displayname>\n",
                             sizeof("</D:displayname>\n") - 1);
        }

        if (ctx->props & NGX_HTTP_DAV_EXT_PROP_GETCONTENTLENGTH) {
            if (!entry->dir) {
                dst = ngx_sprintf(dst, "<D:getcontentlength>%O"
                                       "</D:getcontentlength>\n", entry->size);
            }
        }

        if (ctx->props & NGX_HTTP_DAV_EXT_PROP_GETLASTMODIFIED) {
            dst = ngx_cpymem(dst, "<D:getlastmodified>",
                             sizeof("<D:getlastmodified>") - 1);
            dst = ngx_http_time(dst, entry->mtime);
            dst = ngx_cpymem(dst, "</D:getlastmodified>\n",
                             sizeof("</D:getlastmodified>\n") - 1);
        }

        if (ctx->props & NGX_HTTP_DAV_EXT_PROP_RESOURCETYPE) {
            dst = ngx_cpymem(dst, "<D:resourcetype>",
                             sizeof("<D:resourcetype>") - 1);

            if (entry->dir) {
                dst = ngx_cpymem(dst, "<D:collection/>",
                                 sizeof("<D:collection/>") - 1);
            }

            dst = ngx_cpymem(dst, "</D:resourcetype>\n",
                             sizeof("</D:resourcetype>\n") - 1);
        }

        if (ctx->props & NGX_HTTP_DAV_EXT_PROP_LOCKDISCOVERY) {
            dst = (u_char *) ngx_http_dav_ext_format_lockdiscovery(r, dst,
                                                                   entry);
        }

        if (ctx->props & NGX_HTTP_DAV_EXT_PROP_SUPPORTEDLOCK) {
            dst = ngx_cpymem(dst, "<D:supportedlock>\n",
                             sizeof("<D:supportedlock>\n") - 1);

            if (entry->lock_supported) {
                dst = ngx_cpymem(dst, supportedlock, sizeof(supportedlock) - 1);
            }

            dst = ngx_cpymem(dst, "</D:supportedlock>\n",
                             sizeof("</D:supportedlock>\n") - 1);
        }
    }

    dst = ngx_cpymem(dst, tail, sizeof(tail) - 1);

    return (uintptr_t) dst;
}


static uintptr_t
ngx_http_dav_ext_format_lockdiscovery(ngx_http_request_t *r, u_char *dst,
    ngx_http_dav_ext_entry_t *entry)
{
    size_t  len;

    if (dst == NULL) {
        if (entry->lock_root.len == 0) {
            return sizeof("<D:lockdiscovery/>\n") - 1;
        }

        len = sizeof("<D:lockdiscovery>\n"
                     "<D:activelock>\n"
                     "<D:locktype><D:write/></D:locktype>\n"
                     "<D:lockscope><D:exclusive/></D:lockscope>\n"
                     "<D:owner></D:owner>\n"
                     "<D:depth>infinity</D:depth>\n"
                     "<D:timeout>Second-</D:timeout>\n"
                     "<D:locktoken><D:href></D:href></D:locktoken>\n"
                     "<D:lockroot><D:href></D:href></D:lockroot>\n"
                     "</D:activelock>\n"
                     "</D:lockdiscovery>\n") - 1;

        /* timeout */
        len += NGX_TIME_T_LEN;

        /* token */
        len += ngx_http_dav_ext_format_token(NULL, entry->lock_token, 0);

        /* lockroot */
        len += entry->lock_root.len + ngx_escape_html(NULL,
                                                      entry->lock_root.data,
                                                      entry->lock_root.len);
        return len;
    }

    if (entry->lock_root.len == 0) {
        dst = ngx_cpymem(dst, "<D:lockdiscovery/>\n",
                         sizeof("<D:lockdiscovery/>\n") - 1);
        return (uintptr_t) dst;
    }

    dst = ngx_cpymem(dst, "<D:lockdiscovery>\n",
                     sizeof("<D:lockdiscovery>\n") - 1);

    dst = ngx_cpymem(dst, "<D:activelock>\n",
                     sizeof("<D:activelock>\n") - 1);

    dst = ngx_cpymem(dst, "<D:locktype><D:write/></D:locktype>\n",
                     sizeof("<D:locktype><D:write/></D:locktype>\n") - 1);

    dst = ngx_cpymem(dst, "<D:lockscope><D:exclusive/></D:lockscope>\n",
                     sizeof("<D:lockscope><D:exclusive/></D:lockscope>\n") - 1);

    dst = ngx_cpymem(dst, "<D:owner></D:owner>\n",
                     sizeof("<D:owner></D:owner>\n") - 1);

    dst = ngx_sprintf(dst, "<D:depth>%s</D:depth>\n",
                     entry->lock_depth ? "infinity" : "0");

    dst = ngx_sprintf(dst, "<D:timeout>Second-%O</D:timeout>\n",
                      entry->lock_timeout);

    dst = ngx_cpymem(dst, "<D:locktoken><D:href>",
                     sizeof("<D:locktoken><D:href>") - 1);
    dst = (u_char *) ngx_http_dav_ext_format_token(dst, entry->lock_token, 0);
    dst = ngx_cpymem(dst, "</D:href></D:locktoken>\n",
                     sizeof("</D:href></D:locktoken>\n") - 1);

    dst = ngx_cpymem(dst, "<D:lockroot><D:href>",
                     sizeof("<D:lockroot><D:href>") - 1);
    dst = (u_char *) ngx_escape_html(dst, entry->lock_root.data,
                                     entry->lock_root.len);
    dst = ngx_cpymem(dst, "</D:href></D:lockroot>\n",
                     sizeof("</D:href></D:lockroot>\n") - 1);

    dst = ngx_cpymem(dst, "</D:activelock>\n</D:lockdiscovery>\n",
                     sizeof("</D:activelock>\n</D:lockdiscovery>\n") - 1);

    return (uintptr_t) dst;
}


static ngx_int_t
ngx_http_dav_ext_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_dav_ext_lock_t *olock = data;

    size_t                    len;
    ngx_http_dav_ext_lock_t  *lock;

    lock = shm_zone->data;

    if (olock) {
        lock->sh = olock->sh;
        lock->shpool = olock->shpool;
        return NGX_OK;
    }

    lock->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        lock->sh = lock->shpool->data;
        return NGX_OK;
    }

    lock->sh = ngx_slab_alloc(lock->shpool, sizeof(ngx_http_dav_ext_lock_sh_t));
    if (lock->sh == NULL) {
        return NGX_ERROR;
    }

    lock->shpool->data = lock->sh;

    ngx_queue_init(&lock->sh->queue);

    len = sizeof(" in dav_ext zone \"\"") + shm_zone->shm.name.len;

    lock->shpool->log_ctx = ngx_slab_alloc(lock->shpool, len);
    if (lock->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(lock->shpool->log_ctx, " in dav_ext zone \"%V\"%Z",
                &shm_zone->shm.name);

    lock->shpool->log_nomem = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_dav_ext_verify_lock(ngx_http_request_t *r, ngx_str_t *uri)
{
    u_char                       *data;
    size_t                        len;
    time_t                        now;
    uint32_t                      token;
    ngx_queue_t                  *q;
    ngx_http_dav_ext_node_t      *node;
    ngx_http_dav_ext_lock_t      *lock;
    ngx_http_dav_ext_loc_conf_t  *dlcf;

    static ngx_str_t token_field = ngx_string("if");

    token = ngx_http_dav_ext_token(r, &token_field);

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_ext_module);

    lock = dlcf->shm_zone->data;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dav_ext verify lock \"%V\", token:%uxD", uri, token);

    now = ngx_time();

    if (uri->len == 0) {
        return NGX_HTTP_BAD_REQUEST;
    }

    data = uri->data;
    len = uri->len;

    if (data[len - 1] == '/') {
        len--;
    }

    ngx_shmtx_lock(&lock->shpool->mutex);

    while (!ngx_queue_empty(&lock->sh->queue)) {
        q = ngx_queue_head(&lock->sh->queue);
        node = (ngx_http_dav_ext_node_t *) q;

        if (node->expire >= now) {
            break;
        }

        ngx_queue_remove(q);
        ngx_slab_free_locked(lock->shpool, node);
    }

    for (q = ngx_queue_head(&lock->sh->queue);
         q != ngx_queue_sentinel(&lock->sh->queue);
         q = ngx_queue_next(q))
    {
        node = (ngx_http_dav_ext_node_t *) q;

        if (len < node->len) {
            continue;
        }

        if (ngx_memcmp(data, node->data, node->len)) {
            continue;
        }

        if (len > node->len) {
            if (data[node->len] != '/') {
                continue;
            }

            if (!node->infinite
                && ngx_strlchr(data + node->len + 1, data + len, '/'))
            {
                continue;
            }
        }

        goto found;
    }

    ngx_shmtx_unlock(&lock->shpool->mutex);

    return NGX_OK;

found:

    if (token == 0) {
        ngx_shmtx_unlock(&lock->shpool->mutex);
        /* XXX body? */
        return 423; /* Locked */
    }

    if (token != node->token) {
        ngx_shmtx_unlock(&lock->shpool->mutex);
        return NGX_HTTP_PRECONDITION_FAILED;
    }

    if (r->method == NGX_HTTP_DELETE && node->len == len) {
        ngx_queue_remove(q);
        ngx_slab_free_locked(lock->shpool, node);
    }

    ngx_shmtx_unlock(&lock->shpool->mutex);

    return NGX_OK;
}


static ngx_int_t
ngx_http_dav_ext_lock_handler(ngx_http_request_t *r)
{
    u_char                       *data, *last;
    size_t                        len, n, root;
    time_t                        now;
    uint32_t                      token;
    ngx_fd_t                      fd;
    ngx_int_t                     rc, depth;
    ngx_str_t                     path;
    ngx_uint_t                    status;
    ngx_queue_t                  *q;
    ngx_file_info_t               fi;
    ngx_http_dav_ext_lock_t      *lock;
    ngx_http_dav_ext_node_t      *node;
    ngx_http_dav_ext_loc_conf_t  *dlcf;

    static ngx_str_t token_field = ngx_string("if");

    token = ngx_http_dav_ext_token(r, &token_field);

    while (token == 0) {
        token = ngx_random();
    }

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_ext_module);

    lock = dlcf->shm_zone->data;

    now = ngx_time();

    rc = ngx_http_dav_ext_depth(r);

    if (rc == NGX_ERROR || rc == 1) {
        return NGX_HTTP_BAD_REQUEST;
    }

    depth = rc;

    if (r->uri.len == 0) {
        return NGX_ERROR;
    }

    data = r->uri.data;
    len = r->uri.len;

    if (data[len - 1] == '/') {
        len--;
    }

    ngx_shmtx_lock(&lock->shpool->mutex);

    while (!ngx_queue_empty(&lock->sh->queue)) {
        q = ngx_queue_head(&lock->sh->queue);
        node = (ngx_http_dav_ext_node_t *) q;

        if (node->expire >= now) {
            break;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http dav_ext lock expire \"%*s\"",
                       node->len, node->data);

        ngx_queue_remove(q);
        ngx_slab_free_locked(lock->shpool, node);
    }

    for (q = ngx_queue_head(&lock->sh->queue);
         q != ngx_queue_sentinel(&lock->sh->queue);
         q = ngx_queue_next(q))
    {
        node = (ngx_http_dav_ext_node_t *) q;

        if (len >= node->len) {
            if (ngx_memcmp(data, node->data, node->len)) {
                continue;
            }

            if (len > node->len) {
                if (data[node->len] != '/') {
                    continue;
                }

                if (!node->infinite
                    && ngx_strlchr(data + node->len + 1, data + len, '/'))
                {
                    continue;
                }
            }

        } else {
            if (ngx_memcmp(node->data, data, len)) {
                continue;
            }

            if (node->data[len] != '/') {
                continue;
            }

            if (depth == 0
                && ngx_strlchr(node->data + len + 1, node->data + node->len,
                               '/'))
            {
                continue;
            }
        }

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http dav_ext lock match \"%*s\" \"%*s\"",
                       node->len, node->data, len, data);

        goto found;
    }

    n = sizeof(ngx_http_dav_ext_node_t) + len - (len ? 1 : 0);

    node = ngx_slab_alloc_locked(lock->shpool, n);
    if (node == NULL) {
        ngx_shmtx_unlock(&lock->shpool->mutex);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memzero(node, sizeof(ngx_http_dav_ext_node_t));

    ngx_memcpy(&node->data, data, len);

    node->len = len;
    node->token = token;
    node->expire = now + lock->timeout;
    node->infinite = (depth ? 1 : 0);

    ngx_queue_insert_tail(&lock->sh->queue, &node->queue);

    ngx_shmtx_unlock(&lock->shpool->mutex);

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    *last = '\0';

    status = NGX_HTTP_OK;

    if (ngx_file_info(path.data, &fi) == NGX_FILE_ERROR) {
        fd = ngx_open_file(path.data, NGX_FILE_RDONLY, NGX_FILE_CREATE_OR_OPEN,
                           NGX_FILE_DEFAULT_ACCESS);

        if (fd == NGX_INVALID_FILE) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                          ngx_open_file_n " \"%s\" failed", path.data);
            return NGX_HTTP_CONFLICT;
        }

        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", path.data);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        status = NGX_HTTP_CREATED;

    } else if (ngx_is_dir(&fi)) {
        return NGX_HTTP_CONFLICT;
    }

    return ngx_http_dav_ext_lock_response(r, status, lock->timeout, depth,
                                          token);

found:

    if (node->token != token) {
        ngx_shmtx_unlock(&lock->shpool->mutex);
        return 423; /* Locked */
    }

    /* refresh */

    node->expire = now + lock->timeout;

    ngx_queue_remove(q);
    ngx_queue_insert_tail(&lock->sh->queue, &node->queue);

    ngx_shmtx_unlock(&lock->shpool->mutex);

    return ngx_http_dav_ext_lock_response(r, NGX_HTTP_OK, lock->timeout,
                                          depth, token);
}


static ngx_int_t
ngx_http_dav_ext_lock_response(ngx_http_request_t *r, ngx_uint_t status,
    time_t timeout, ngx_uint_t depth, uint32_t token)
{
    size_t                     len;
    u_char                    *p;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t                cl;
    ngx_table_elt_t           *h;
    ngx_http_dav_ext_entry_t   entry;

    static u_char head[] =
        "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n"
        "<D:prop xmlns:D=\"DAV:\">\n";

    static u_char tail[] =
        "</D:prop>\n";

    ngx_memzero(&entry, sizeof(ngx_http_dav_ext_entry_t));

    entry.lock_timeout = timeout;
    entry.lock_root = r->uri;
    entry.lock_depth = depth;
    entry.lock_token = token;

    len = sizeof(head) - 1
          + ngx_http_dav_ext_format_lockdiscovery(r, NULL, &entry)
          + sizeof(tail) - 1;

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last = ngx_cpymem(b->last, head, sizeof(head) - 1);

    b->last = (u_char *) ngx_http_dav_ext_format_lockdiscovery(r, b->last,
                                                               &entry);

    b->last = ngx_cpymem(b->last, tail, sizeof(tail) - 1);

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    cl.buf = b;
    cl.next = NULL;

    r->headers_out.status = status;

    r->headers_out.content_length_n = b->last - b->pos;

    r->headers_out.content_type_len = sizeof("text/xml") - 1;
    ngx_str_set(&r->headers_out.content_type, "text/xml");
    r->headers_out.content_type_lowcase = NULL;

    ngx_str_set(&r->headers_out.charset, "utf-8");

    p = ngx_pnalloc(r->pool, ngx_http_dav_ext_format_token(NULL, token, 1));
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_str_set(&h->key, "Lock-Token");

    h->value.data = p;
    h->value.len = (u_char *) ngx_http_dav_ext_format_token(p, token, 1) - p;
    h->hash = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &cl);
}


static ngx_int_t
ngx_http_dav_ext_unlock_handler(ngx_http_request_t *r)
{
    time_t                        now;
    size_t                        len;
    u_char                       *data;
    uint32_t                      token;
    ngx_queue_t                  *q;
    ngx_http_dav_ext_lock_t      *lock;
    ngx_http_dav_ext_node_t      *node;
    ngx_http_dav_ext_loc_conf_t  *dlcf;

    static ngx_str_t token_field = ngx_string("lock-token");

    token = ngx_http_dav_ext_token(r, &token_field);

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_ext_module);

    lock = dlcf->shm_zone->data;

    now = ngx_time();

    if (r->uri.len == 0) {
        return NGX_HTTP_BAD_REQUEST;
    }

    data = r->uri.data;
    len = r->uri.len;

    if (data[len - 1] == '/') {
        len--;
    }

    ngx_shmtx_lock(&lock->shpool->mutex);

    while (!ngx_queue_empty(&lock->sh->queue)) {
        q = ngx_queue_head(&lock->sh->queue);
        node = (ngx_http_dav_ext_node_t *) q;

        if (node->expire >= now) {
            break;
        }

        ngx_queue_remove(q);
        ngx_slab_free_locked(lock->shpool, node);
    }

    for (q = ngx_queue_head(&lock->sh->queue);
         q != ngx_queue_sentinel(&lock->sh->queue);
         q = ngx_queue_next(q))
    {
        node = (ngx_http_dav_ext_node_t *) q;

        if (node->len == len && ngx_memcmp(node->data, data, len) == 0) {
            goto found;
        }
    }

    ngx_shmtx_unlock(&lock->shpool->mutex);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dav_ext unlock no match \"%*s\"", len, data);

    return NGX_HTTP_NO_CONTENT;

found:

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dav_ext unlock match \"%*s\", tokens:%uxD %uxD",
                   len, data, token, node->token);

    if (token == node->token) {
        ngx_queue_remove(q);
        ngx_slab_free_locked(lock->shpool, node);
    }

    ngx_shmtx_unlock(&lock->shpool->mutex);

    return NGX_HTTP_NO_CONTENT;
}


static void *
ngx_http_dav_ext_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_dav_ext_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dav_ext_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->shm_zone = NULL;
     */

    return conf;
}


static char *
ngx_http_dav_ext_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_dav_ext_loc_conf_t  *prev = parent;
    ngx_http_dav_ext_loc_conf_t  *conf = child;

    ngx_conf_merge_bitmask_value(conf->methods, prev->methods,
                         (NGX_CONF_BITMASK_SET|NGX_HTTP_DAV_EXT_OFF));

    if (conf->shm_zone == NULL) {
        conf->shm_zone = prev->shm_zone;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_dav_ext_lock_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                   *p;
    time_t                    timeout;
    ssize_t                   size;
    ngx_str_t                *value, name, s;
    ngx_uint_t                i;
    ngx_shm_zone_t           *shm_zone;
    ngx_http_dav_ext_lock_t  *lock;

    value = cf->args->elts;

    name.len = 0;
    size = 0;
    timeout = 60;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            name.data = value[i].data + 5;

            p = (u_char *) ngx_strchr(name.data, ':');

            if (p == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            name.len = p - name.data;

            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            size = ngx_parse_size(&s);

            if (size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            if (size < (ssize_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "zone \"%V\" is too small", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {

            s.len = value[i].len - 8;
            s.data = value[i].data + 8;

            timeout = ngx_parse_time(&s, 1);
            if (timeout == (time_t) NGX_ERROR || timeout == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid timeout value \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    lock = ngx_pcalloc(cf->pool, sizeof(ngx_http_dav_ext_lock_t));
    if (lock == NULL) {
        return NGX_CONF_ERROR;
    }

    lock->timeout = timeout;

    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_dav_ext_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate zone \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_dav_ext_init_zone;
    shm_zone->data = lock;

    return NGX_CONF_OK;
}


static char *
ngx_http_dav_ext_lock(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_dav_ext_loc_conf_t *dlcf = conf;

    ngx_str_t       *value, s;
    ngx_uint_t       i;
    ngx_shm_zone_t  *shm_zone;

    if (dlcf->shm_zone) {
        return "is duplicate";
    }

    value = cf->args->elts;

    shm_zone = NULL;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            shm_zone = ngx_shared_memory_add(cf, &s, 0,
                                             &ngx_http_dav_ext_module);
            if (shm_zone == NULL) {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (shm_zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter", &cmd->name);
        return NGX_CONF_ERROR;
    }

    dlcf->shm_zone = shm_zone;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_dav_ext_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_dav_ext_precontent_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_dav_ext_content_handler;

    return NGX_OK;
}
