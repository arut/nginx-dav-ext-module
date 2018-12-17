
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <libxml/parser.h>


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
    time_t                       mtime;
    off_t                        size;

    time_t                       lock_expire;
    ngx_str_t                    lock_root;
    uint32_t                     lock_token;

    unsigned                     dir:1;
    unsigned                     lock_supported:1;
    unsigned                     lock_infinite:1;
} ngx_http_dav_ext_entry_t;


typedef struct {
    ngx_uint_t                   nodes;
    ngx_uint_t                   props;
} ngx_http_dav_ext_xml_ctx_t;


typedef struct {
    ngx_uint_t                   methods;
    ngx_shm_zone_t              *shm_zone;
} ngx_http_dav_ext_loc_conf_t;


typedef struct {
    ngx_queue_t                  queue;
    uint32_t                     token;
    time_t                       expire;
    ngx_uint_t                   infinite; /* unsigned  infinite:1; */
    size_t                       len;
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
static ngx_int_t ngx_http_dav_ext_strip_uri(ngx_http_request_t *r,
    ngx_str_t *uri);
static ngx_int_t ngx_http_dav_ext_verify_lock(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_uint_t delete_lock);
static ngx_http_dav_ext_node_t *ngx_http_dav_ext_lock_lookup(
    ngx_http_request_t *r, ngx_http_dav_ext_lock_t *lock, ngx_str_t *uri,
    ngx_int_t depth);

static ngx_int_t ngx_http_dav_ext_content_handler(ngx_http_request_t *r);
static void ngx_http_dav_ext_propfind_handler(ngx_http_request_t *r);
static void ngx_http_dav_ext_propfind_xml_start(void *data,
    const xmlChar *localname, const xmlChar *prefix, const xmlChar *uri,
    int nb_namespaces, const xmlChar **namespaces, int nb_attributes,
    int nb_defaulted, const xmlChar **attributes);
static void ngx_http_dav_ext_propfind_xml_end(void *data,
    const xmlChar *localname, const xmlChar *prefix, const xmlChar *uri);
static ngx_int_t ngx_http_dav_ext_propfind(ngx_http_request_t *r,
    ngx_uint_t props);
static ngx_int_t ngx_http_dav_ext_set_locks(ngx_http_request_t *r,
    ngx_http_dav_ext_entry_t *entry);
static ngx_int_t ngx_http_dav_ext_propfind_response(ngx_http_request_t *r,
    ngx_array_t *entries, ngx_uint_t props);
static ngx_int_t ngx_http_dav_ext_lock_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_ext_lock_response(ngx_http_request_t *r,
    ngx_uint_t status, time_t timeout, ngx_uint_t depth, uint32_t token);
static ngx_int_t ngx_http_dav_ext_unlock_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_dav_ext_depth(ngx_http_request_t *r,
    ngx_int_t default_depth);
static uint32_t ngx_http_dav_ext_lock_token(ngx_http_request_t *r);
static uint32_t ngx_http_dav_ext_if(ngx_http_request_t *r, ngx_str_t *uri);
static uintptr_t ngx_http_dav_ext_format_propfind(ngx_http_request_t *r,
    u_char *dst, ngx_http_dav_ext_entry_t *entry, ngx_uint_t props);
static uintptr_t ngx_http_dav_ext_format_lockdiscovery(ngx_http_request_t *r,
    u_char *dst, ngx_http_dav_ext_entry_t *entry);
static uintptr_t ngx_http_dav_ext_format_token(u_char *dst, uint32_t token,
    ngx_uint_t brackets);

static ngx_int_t ngx_http_dav_ext_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);
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
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
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
    ngx_str_t                     uri;
    ngx_int_t                     rc;
    ngx_uint_t                    delete_lock;
    ngx_table_elt_t              *dest;
    ngx_http_dav_ext_loc_conf_t  *dlcf;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_ext_module);

    if (dlcf->shm_zone == NULL) {
        return NGX_DECLINED;
    }

    if (r->method & (NGX_HTTP_PUT|NGX_HTTP_DELETE|NGX_HTTP_MKCOL|NGX_HTTP_MOVE))
    {
        delete_lock = (r->method & (NGX_HTTP_DELETE|NGX_HTTP_MOVE)) ? 1 : 0;

        rc = ngx_http_dav_ext_verify_lock(r, &r->uri, delete_lock);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    if (r->method & (NGX_HTTP_MOVE|NGX_HTTP_COPY)) {
        dest = r->headers_in.destination;
        if (dest == NULL) {
            return NGX_DECLINED;
        }

        uri.data = dest->value.data;
        uri.len = dest->value.len;

        if (ngx_http_dav_ext_strip_uri(r, &uri) != NGX_OK) {
            return NGX_DECLINED;
        }

        rc = ngx_http_dav_ext_verify_lock(r, &uri, 0);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_dav_ext_strip_uri(ngx_http_request_t *r, ngx_str_t *uri)
{
    u_char  *p, *last, *host;
    size_t   len;

    if (uri->data[0] == '/') {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http dav_ext strip uri:\"%V\" unchanged", uri);
        return NGX_OK;
    }

    len = r->headers_in.server.len;

    if (len == 0) {
        goto failed;
    }

#if (NGX_HTTP_SSL)

    if (r->connection->ssl) {
        if (ngx_strncmp(uri->data, "https://", sizeof("https://") - 1) != 0) {
            goto failed;
        }

        host = uri->data + sizeof("https://") - 1;

    } else
#endif
    {
        if (ngx_strncmp(uri->data, "http://", sizeof("http://") - 1) != 0) {
            goto failed;
        }

        host = uri->data + sizeof("http://") - 1;
    }

    if (ngx_strncmp(host, r->headers_in.server.data, len) != 0) {
        goto failed;
    }

    last = uri->data + uri->len;

    for (p = host + len; p != last; p++) {
        if (*p == '/') {
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http dav_ext strip uri \"%V\" \"%*s\"",
                           uri, last - p, p);

            uri->data = p;
            uri->len = last - p;

            return NGX_OK;
        }
    }

failed:

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dav_ext strip uri \"%V\" failed", uri);

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_dav_ext_verify_lock(ngx_http_request_t *r, ngx_str_t *uri,
    ngx_uint_t delete_lock)
{
    uint32_t                      token;
    ngx_http_dav_ext_node_t      *node;
    ngx_http_dav_ext_lock_t      *lock;
    ngx_http_dav_ext_loc_conf_t  *dlcf;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dav_ext verify lock \"%V\"", uri);

    token = ngx_http_dav_ext_if(r, uri);

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_ext_module);
    lock = dlcf->shm_zone->data;

    ngx_shmtx_lock(&lock->shpool->mutex);

    node = ngx_http_dav_ext_lock_lookup(r, lock, uri, -1);
    if (node == NULL) {
        ngx_shmtx_unlock(&lock->shpool->mutex);
        return NGX_OK;
    }

    if (token == 0) {
        ngx_shmtx_unlock(&lock->shpool->mutex);
        return 423; /* Locked */
    }

    if (token != node->token) {
        ngx_shmtx_unlock(&lock->shpool->mutex);
        return NGX_HTTP_PRECONDITION_FAILED;
    }

    /*
     * RFC4918:
     * If a request causes the lock-root of any lock to become an
     * unmapped URL, then the lock MUST also be deleted by that request.
     */

    if (delete_lock && node->len == uri->len) {
        ngx_queue_remove(&node->queue);
        ngx_slab_free_locked(lock->shpool, node);
    }

    ngx_shmtx_unlock(&lock->shpool->mutex);

    return NGX_OK;
}


static ngx_http_dav_ext_node_t *
ngx_http_dav_ext_lock_lookup(ngx_http_request_t *r,
    ngx_http_dav_ext_lock_t *lock, ngx_str_t *uri, ngx_int_t depth)
{
    time_t                    now;
    ngx_queue_t              *q;
    ngx_http_dav_ext_node_t  *node;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dav_ext lock lookup \"%V\"", uri);

    if (uri->len == 0) {
        return NULL;
    }

    now = ngx_time();

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

        if (uri->len >= node->len) {
            if (ngx_memcmp(uri->data, node->data, node->len)) {
                continue;
            }

            if (uri->len > node->len) {
                if (node->data[node->len - 1] != '/') {
                    continue;
                }

                if (!node->infinite
                    && ngx_strlchr(uri->data + node->len,
                                   uri->data + uri->len - 1, '/'))
                {
                    continue;
                }
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http dav_ext lock found \"%*s\"",
                           node->len, node->data);

            return node;
        }

        /* uri->len < node->len */

        if (depth >= 0) {
            if (ngx_memcmp(node->data, uri->data, uri->len)) {
                continue;
            }

            if (uri->data[uri->len - 1] != '/') {
                continue;
            }

            if (depth == 0
                && ngx_strlchr(node->data + uri->len,
                               node->data + node->len - 1, '/'))
            {
                continue;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http dav_ext lock found \"%*s\"",
                           node->len, node->data);

            return node;
        }
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dav_ext lock not found");

    return NULL;
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
         * Body is expected to carry the requested lock type, but
         * since we only support write/exclusive locks, we ignore it.
         * Ideally we could throw an error if a lock of another type
         * is requested, but the amount of work required for that is
         * not worth it.
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
    off_t                        len;
    ngx_buf_t                   *b;
    ngx_chain_t                 *cl;
    xmlSAXHandler                sax;
    xmlParserCtxtPtr             pctx;
    ngx_http_dav_ext_xml_ctx_t   xctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dav_ext propfind handler");

    ngx_memzero(&xctx, sizeof(ngx_http_dav_ext_xml_ctx_t));
    ngx_memzero(&sax, sizeof(xmlSAXHandler));

    sax.initialized = XML_SAX2_MAGIC;
    sax.startElementNs = ngx_http_dav_ext_propfind_xml_start;
    sax.endElementNs = ngx_http_dav_ext_propfind_xml_end;

    pctx = xmlCreatePushParserCtxt(&sax, &xctx, NULL, 0, NULL);
    if (pctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "xmlCreatePushParserCtxt() failed");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    len = 0;

    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        b = cl->buf;

        if (b->in_file) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "PROPFIND client body is in file, "
                          "you may want to increase client_body_buffer_size");
            xmlFreeParserCtxt(pctx);
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (ngx_buf_special(b)) {
            continue;
        }

        len += b->last - b->pos;

        if (xmlParseChunk(pctx, (const char *) b->pos, b->last - b->pos,
                          b->last_buf))
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "xmlParseChunk() failed");
            xmlFreeParserCtxt(pctx);
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            return;
        }
    }

    xmlFreeParserCtxt(pctx);

    if (len == 0) {

        /*
         * For easier debugging treat bodiless requests
         * as if they expect all properties.
         */

        xctx.props = NGX_HTTP_DAV_EXT_PROP_ALL;
    }

    ngx_http_finalize_request(r, ngx_http_dav_ext_propfind(r, xctx.props));
}


static void
ngx_http_dav_ext_propfind_xml_start(void *data, const xmlChar *localname,
    const xmlChar *prefix, const xmlChar *uri, int nb_namespaces,
    const xmlChar **namespaces, int nb_attributes, int nb_defaulted,
    const xmlChar **attributes)
{
    ngx_http_dav_ext_xml_ctx_t *xctx = data;

    if (ngx_strcmp(localname, "propfind") == 0) {
        xctx->nodes ^= NGX_HTTP_DAV_EXT_NODE_PROPFIND;
    }

    if (ngx_strcmp(localname, "prop") == 0) {
        xctx->nodes ^= NGX_HTTP_DAV_EXT_NODE_PROP;
    }

    if (ngx_strcmp(localname, "propname") == 0) {
        xctx->nodes ^= NGX_HTTP_DAV_EXT_NODE_PROPNAME;
    }

    if (ngx_strcmp(localname, "allprop") == 0) {
        xctx->nodes ^= NGX_HTTP_DAV_EXT_NODE_ALLPROP;
    }
}


static void
ngx_http_dav_ext_propfind_xml_end(void *data, const xmlChar *localname,
    const xmlChar *prefix, const xmlChar *uri)
{
    ngx_http_dav_ext_xml_ctx_t *xctx = data;

    if (xctx->nodes & NGX_HTTP_DAV_EXT_NODE_PROPFIND) {

        if (xctx->nodes & NGX_HTTP_DAV_EXT_NODE_PROP) {
            if (ngx_strcmp(localname, "displayname") == 0) {
                xctx->props |= NGX_HTTP_DAV_EXT_PROP_DISPLAYNAME;
            }

            if (ngx_strcmp(localname, "getcontentlength") == 0) {
                xctx->props |= NGX_HTTP_DAV_EXT_PROP_GETCONTENTLENGTH;
            }

            if (ngx_strcmp(localname, "getlastmodified") == 0) {
                xctx->props |= NGX_HTTP_DAV_EXT_PROP_GETLASTMODIFIED;
            }

            if (ngx_strcmp(localname, "resourcetype") == 0) {
                xctx->props |= NGX_HTTP_DAV_EXT_PROP_RESOURCETYPE;
            }

            if (ngx_strcmp(localname, "lockdiscovery") == 0) {
                xctx->props |= NGX_HTTP_DAV_EXT_PROP_LOCKDISCOVERY;
            }

            if (ngx_strcmp(localname, "supportedlock") == 0) {
                xctx->props |= NGX_HTTP_DAV_EXT_PROP_SUPPORTEDLOCK;
            }
        }

        if (xctx->nodes & NGX_HTTP_DAV_EXT_NODE_PROPNAME) {
            xctx->props |= NGX_HTTP_DAV_EXT_PROP_NAMES;
        }

        if (xctx->nodes & NGX_HTTP_DAV_EXT_NODE_ALLPROP) {
            xctx->props = NGX_HTTP_DAV_EXT_PROP_ALL;
        }
    }

    ngx_http_dav_ext_propfind_xml_start(data, localname, prefix, uri,
                                        0, NULL, 0, 0, NULL);
}


static ngx_int_t
ngx_http_dav_ext_propfind(ngx_http_request_t *r, ngx_uint_t props)
{
    size_t                     root, allocated;
    u_char                    *p, *last, *filename;
    ngx_int_t                  rc;
    ngx_err_t                  err;
    ngx_str_t                  path, name;
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

    rc = ngx_http_dav_ext_depth(r, 0);

    if (rc == NGX_ERROR) {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (rc == NGX_MAX_INT_T_VALUE) {

        /*
         * RFC4918:
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

    entry = ngx_array_push(&entries);
    if (entry == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memzero(entry, sizeof(ngx_http_dav_ext_entry_t));

    entry->uri = r->uri;
    entry->name = name;
    entry->dir = ngx_is_dir(&fi);
    entry->mtime = ngx_file_mtime(&fi);
    entry->size = ngx_file_size(&fi);

    if (ngx_http_dav_ext_set_locks(r, entry) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dav_ext propfind name:\"%V\", uri:\"%V\"",
                   &entry->name, &entry->uri);

    if (depth == 0 || !entry->dir) {
        return ngx_http_dav_ext_propfind_response(r, &entries, props);
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
                *last++ = '/';
            }

            ngx_cpystrn(last, name.data, name.len + 1);

            if (ngx_de_info(filename, &dir) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                              ngx_de_info_n " \"%s\" failed", filename);
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                break;
            }
        }

        p = ngx_pnalloc(r->pool, name.len);
        if (p == NULL) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        ngx_memcpy(p, name.data, name.len);
        entry->name.data = p;
        entry->name.len = name.len;

        p = ngx_pnalloc(r->pool, r->uri.len + 1 + name.len + 1);
        if (p == NULL) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        entry->uri.data = p;

        p = ngx_cpymem(p, r->uri.data, r->uri.len);
        if (r->uri.len && r->uri.data[r->uri.len - 1] != '/') {
            *p++ = '/';
        }

        p = ngx_cpymem(p, name.data, name.len);
        if (ngx_de_is_dir(&dir)) {
            *p++ = '/';
        }

        entry->uri.len = p - entry->uri.data;
        entry->dir = ngx_de_is_dir(&dir);
        entry->mtime = ngx_de_mtime(&dir);
        entry->size = ngx_de_size(&dir);

        if (ngx_http_dav_ext_set_locks(r, entry) != NGX_OK) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http dav_ext propfind child name:\"%V\", uri:\"%V\"",
                       &entry->name, &entry->uri);
    }

    if (ngx_close_dir(&dir) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_close_dir_n " \"%V\" failed", &path);
    }

    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_http_dav_ext_propfind_response(r, &entries, props);
}


static ngx_int_t
ngx_http_dav_ext_set_locks(ngx_http_request_t *r,
    ngx_http_dav_ext_entry_t *entry)
{
    ngx_http_dav_ext_node_t      *node;
    ngx_http_dav_ext_lock_t      *lock;
    ngx_http_dav_ext_loc_conf_t  *dlcf;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_ext_module);

    if (dlcf->shm_zone == NULL) {
        entry->lock_supported = 0;
        return NGX_OK;
    }

    entry->lock_supported = 1;

    lock = dlcf->shm_zone->data;

    ngx_shmtx_lock(&lock->shpool->mutex);

    node = ngx_http_dav_ext_lock_lookup(r, lock, &entry->uri, -1);
    if (node == NULL) {
        ngx_shmtx_unlock(&lock->shpool->mutex);
        return NGX_OK;
    }

    entry->lock_infinite = node->infinite ? 1 : 0;
    entry->lock_expire = node->expire;
    entry->lock_token = node->token;

    entry->lock_root.data = ngx_pnalloc(r->pool, node->len);
    if (entry->lock_root.data == NULL) {
        ngx_shmtx_unlock(&lock->shpool->mutex);
        return NGX_ERROR;
    }

    ngx_memcpy(entry->lock_root.data, node->data, node->len);
    entry->lock_root.len = node->len;

    ngx_shmtx_unlock(&lock->shpool->mutex);

    return NGX_OK;
}


static ngx_int_t
ngx_http_dav_ext_propfind_response(ngx_http_request_t *r, ngx_array_t *entries,
    ngx_uint_t props)
{
    size_t                     len;
    u_char                    *p;
    uintptr_t                  escape;
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

    entry = entries->elts;

    for (n = 0; n < entries->nelts; n++) {
        escape = 2 * ngx_escape_uri(NULL, entry[n].uri.data, entry[n].uri.len,
                                    NGX_ESCAPE_URI);
        if (escape == 0) {
            continue;
        }

        p = ngx_pnalloc(r->pool, entry[n].uri.len + escape);
        if (p == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        entry[n].uri.len = (u_char *) ngx_escape_uri(p, entry[n].uri.data,
                                                     entry[n].uri.len,
                                                     NGX_ESCAPE_URI)
                           - p;
        entry[n].uri.data = p;
    }

    len = sizeof(head) - 1 + sizeof(tail) - 1;

    for (n = 0; n < entries->nelts; n++) {
        len += ngx_http_dav_ext_format_propfind(r, NULL, &entry[n], props);
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last = ngx_cpymem(b->last, head, sizeof(head) - 1);

    for (n = 0; n < entries->nelts; n++) {
        b->last = (u_char *) ngx_http_dav_ext_format_propfind(r, b->last,
                                                              &entry[n], props);
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


static ngx_int_t
ngx_http_dav_ext_lock_handler(ngx_http_request_t *r)
{
    u_char                       *last;
    size_t                        n, root;
    time_t                        now;
    uint32_t                      token, new_token;
    ngx_fd_t                      fd;
    ngx_int_t                     rc, depth;
    ngx_str_t                     path;
    ngx_uint_t                    status;
    ngx_file_info_t               fi;
    ngx_http_dav_ext_lock_t      *lock;
    ngx_http_dav_ext_node_t      *node;
    ngx_http_dav_ext_loc_conf_t  *dlcf;

    if (r->uri.len == 0) {
        return NGX_HTTP_BAD_REQUEST;
    }

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_ext_module);
    lock = dlcf->shm_zone->data;

    /*
     * RFC4918:
     * If no Depth header is submitted on a LOCK request, then the request
     * MUST act as if a "Depth:infinity" had been submitted.
     */

    rc = ngx_http_dav_ext_depth(r, NGX_MAX_INT_T_VALUE);

    if (rc == NGX_ERROR || rc == 1) {

        /*
         * RFC4918:
         * Values other than 0 or infinity MUST NOT be used with the Depth
         * header on a LOCK method.
         */

        return NGX_HTTP_BAD_REQUEST;
    }

    depth = rc;

    token = ngx_http_dav_ext_if(r, &r->uri);

    do {
        new_token = ngx_random();
    } while (new_token == 0);

    now = ngx_time();

    ngx_shmtx_lock(&lock->shpool->mutex);

    node = ngx_http_dav_ext_lock_lookup(r, lock, &r->uri, depth);

    if (node) {
        if (token == 0) {
            ngx_shmtx_unlock(&lock->shpool->mutex);
            return 423; /* Locked */
        }

        if (node->token != token) {
            ngx_shmtx_unlock(&lock->shpool->mutex);
            return NGX_HTTP_PRECONDITION_FAILED;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http dav_ext refresh lock");

        node->expire = now + lock->timeout;

        ngx_queue_remove(&node->queue);
        ngx_queue_insert_tail(&lock->sh->queue, &node->queue);

        ngx_shmtx_unlock(&lock->shpool->mutex);

        return ngx_http_dav_ext_lock_response(r, NGX_HTTP_OK, lock->timeout,
                                              depth, token);
    }

    n = sizeof(ngx_http_dav_ext_node_t) + r->uri.len - 1;

    node = ngx_slab_alloc_locked(lock->shpool, n);
    if (node == NULL) {
        ngx_shmtx_unlock(&lock->shpool->mutex);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memzero(node, sizeof(ngx_http_dav_ext_node_t));

    ngx_memcpy(&node->data, r->uri.data, r->uri.len);

    node->len = r->uri.len;
    node->token = new_token;
    node->expire = now + lock->timeout;
    node->infinite = (depth ? 1 : 0);

    ngx_queue_insert_tail(&lock->sh->queue, &node->queue);

    ngx_shmtx_unlock(&lock->shpool->mutex);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dav_ext add lock");

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    *last = '\0';

    status = NGX_HTTP_OK;

    if (ngx_file_info(path.data, &fi) == NGX_FILE_ERROR) {

        /*
         * RFC4918:
         * A successful lock request to an unmapped URL MUST result in the
         * creation of a locked (non-collection) resource with empty content.
         */

        fd = ngx_open_file(path.data, NGX_FILE_RDONLY, NGX_FILE_CREATE_OR_OPEN,
                           NGX_FILE_DEFAULT_ACCESS);

        if (fd == NGX_INVALID_FILE) {

            /*
             * RFC4918:
             * 409 (Conflict) - A resource cannot be created at the destination
             * until one or more intermediate collections have been created.
             * The server MUST NOT create those intermediate collections
             * automatically.
             */

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
    }

    return ngx_http_dav_ext_lock_response(r, status, lock->timeout, depth,
                                          new_token);
}


static ngx_int_t
ngx_http_dav_ext_lock_response(ngx_http_request_t *r, ngx_uint_t status,
    time_t timeout, ngx_uint_t depth, uint32_t token)
{
    size_t                     len;
    time_t                     now;
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

    now = ngx_time();

    ngx_memzero(&entry, sizeof(ngx_http_dav_ext_entry_t));

    entry.lock_expire = now + timeout;
    entry.lock_root = r->uri;
    entry.lock_infinite = depth ? 1 : 0;
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

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_str_set(&h->key, "Lock-Token");

    p = ngx_pnalloc(r->pool, ngx_http_dav_ext_format_token(NULL, token, 1));
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

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
    uint32_t                      token;
    ngx_http_dav_ext_lock_t      *lock;
    ngx_http_dav_ext_node_t      *node;
    ngx_http_dav_ext_loc_conf_t  *dlcf;

    token = ngx_http_dav_ext_lock_token(r);

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_ext_module);
    lock = dlcf->shm_zone->data;

    ngx_shmtx_lock(&lock->shpool->mutex);

    node = ngx_http_dav_ext_lock_lookup(r, lock, &r->uri, -1);

    if (node == NULL || node->token != token) {
        ngx_shmtx_unlock(&lock->shpool->mutex);
        return NGX_HTTP_NO_CONTENT;
    }

    ngx_queue_remove(&node->queue);
    ngx_slab_free_locked(lock->shpool, node);

    ngx_shmtx_unlock(&lock->shpool->mutex);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dav_ext delete lock");

    return NGX_HTTP_NO_CONTENT;
}


static ngx_int_t
ngx_http_dav_ext_depth(ngx_http_request_t *r, ngx_int_t default_depth)
{
    ngx_table_elt_t  *depth;

    depth = r->headers_in.depth;

    if (depth == NULL) {
        return default_depth;
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
ngx_http_dav_ext_lock_token(ngx_http_request_t *r)
{
    u_char           *p, ch;
    uint32_t          token;
    ngx_uint_t        i, n;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header;

    static u_char name[] = "lock-token";

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

        for (n = 0; n < sizeof(name) - 1 && n < header[i].key.len; n++) {
            ch = header[i].key.data[n];

            if (ch >= 'A' && ch <= 'Z') {
                ch |= 0x20;
            }

            if (name[n] != ch) {
                break;
            }
        }

        if (n == sizeof(name) - 1 && n == header[i].key.len) {
            p = header[i].value.data;

            if (ngx_strncmp(p, "<urn:", 5)) {
                return 0;
            }

            p += 5;
            token = 0;

            for (n = 0; n < 8; n++) {
                ch = *p++;

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

            if (*p != '>') {
                return 0;
            }

            return token;
        }
    }

    return 0;
}


static uint32_t
ngx_http_dav_ext_if(ngx_http_request_t *r, ngx_str_t *uri)
{
    u_char           *p, ch;
    uint32_t          token;
    ngx_str_t         tag;
    ngx_uint_t        i, n;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header;

    static u_char name[] = "if";

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dav_ext if \"%V\"", uri);

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

        for (n = 0; n < sizeof(name) - 1 && n < header[i].key.len; n++) {
            ch = header[i].key.data[n];

            if (ch >= 'A' && ch <= 'Z') {
                ch |= 0x20;
            }

            if (name[n] != ch) {
                break;
            }
        }

        if (n == sizeof(name) - 1 && n == header[i].key.len) {
            p = header[i].value.data;
            tag = r->uri;

            while (*p != '\0') {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http dav_ext if list \"%s\"", p);

                while (*p == ' ') { p++; }

                if (*p == '<') {
                    tag.data = ++p;

                    while (*p != '\0' && *p != '>') { p++; }

                    if (*p == '\0') {
                        break;
                    }

                    tag.len = p++ - tag.data;

                    (void) ngx_http_dav_ext_strip_uri(r, &tag);

                    while (*p == ' ') { p++; }
                }

                if (*p != '(') {
                    break;
                }

                p++;

                if (tag.len == 0
                    || tag.len > uri->len
                    || (tag.len < uri->len && tag.data[tag.len - 1] != '/')
                    || ngx_memcmp(tag.data, uri->data, tag.len))
                {
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "http dav_ext if tag mismatch \"%V\"", &tag);

                    while (*p != '\0' && *p != ')') { p++; }

                    if (*p == ')') {
                        p++;
                    }

                    continue;
                }

                while (*p != '\0') {
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "http dav_ext if condition \"%s\"", p);

                    while (*p == ' ') { p++; }

                    if (ngx_strncmp(p, "Not", 3) == 0) {
                        p += 3;
                        while (*p == ' ') { p++; }
                        goto next;
                    }

                    if (*p == '[') {
                        p++;
                        while (*p != '\0' && *p != ']') { p++; }
                        goto next;
                    }

                    if (ngx_strncmp(p, "<urn:", 5)) {
                        goto next;
                    }

                    p += 5;
                    token = 0;

                    for (n = 0; n < 8; n++) {
                        ch = *p++;

                        if (ch >= '0' && ch <= '9') {
                            token = token * 16 + (ch - '0');
                            continue;
                        }

                        ch = (u_char) (ch | 0x20);

                        if (ch >= 'a' && ch <= 'f') {
                            token = token * 16 + (ch - 'a' + 10);
                            continue;
                        }

                        goto next;
                    }

                    if (*p != '>') {
                        goto next;
                    }

                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "http dav_ext if token: %uxD", token);

                    return token;

                next:

                    while (*p != '\0' && *p != ' ' && *p != ')') { p++; }

                    if (*p == ')') {
                        p++;
                        break;
                    }
                }
            }

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http dav_ext if header mismatch");
        }
    }

    return 0;
}


static uintptr_t
ngx_http_dav_ext_format_propfind(ngx_http_request_t *r, u_char *dst,
    ngx_http_dav_ext_entry_t *entry, ngx_uint_t props)
{
    size_t  len;

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

    if (dst == NULL) {
        len = sizeof(head) - 1
              + sizeof(prop) - 1
              + sizeof(tail) - 1;

        len += entry->uri.len + ngx_escape_html(NULL, entry->uri.data,
                                                entry->uri.len);

        if (props & NGX_HTTP_DAV_EXT_PROP_NAMES) {
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

            /* lockdiscovery */
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

    if (props & NGX_HTTP_DAV_EXT_PROP_NAMES) {
        dst = ngx_cpymem(dst, names, sizeof(names) - 1);

    } else {
        if (props & NGX_HTTP_DAV_EXT_PROP_DISPLAYNAME) {
            dst = ngx_cpymem(dst, "<D:displayname>",
                             sizeof("<D:displayname>") - 1);
            dst = (u_char *) ngx_escape_html(dst, entry->name.data,
                                             entry->name.len);
            dst = ngx_cpymem(dst, "</D:displayname>\n",
                             sizeof("</D:displayname>\n") - 1);
        }

        if (props & NGX_HTTP_DAV_EXT_PROP_GETCONTENTLENGTH) {
            if (!entry->dir) {
                dst = ngx_sprintf(dst, "<D:getcontentlength>%O"
                                       "</D:getcontentlength>\n", entry->size);
            }
        }

        if (props & NGX_HTTP_DAV_EXT_PROP_GETLASTMODIFIED) {
            dst = ngx_cpymem(dst, "<D:getlastmodified>",
                             sizeof("<D:getlastmodified>") - 1);
            dst = ngx_http_time(dst, entry->mtime);
            dst = ngx_cpymem(dst, "</D:getlastmodified>\n",
                             sizeof("</D:getlastmodified>\n") - 1);
        }

        if (props & NGX_HTTP_DAV_EXT_PROP_RESOURCETYPE) {
            dst = ngx_cpymem(dst, "<D:resourcetype>",
                             sizeof("<D:resourcetype>") - 1);

            if (entry->dir) {
                dst = ngx_cpymem(dst, "<D:collection/>",
                                 sizeof("<D:collection/>") - 1);
            }

            dst = ngx_cpymem(dst, "</D:resourcetype>\n",
                             sizeof("</D:resourcetype>\n") - 1);
        }

        if (props & NGX_HTTP_DAV_EXT_PROP_LOCKDISCOVERY) {
            dst = (u_char *) ngx_http_dav_ext_format_lockdiscovery(r, dst,
                                                                   entry);
        }

        if (props & NGX_HTTP_DAV_EXT_PROP_SUPPORTEDLOCK) {
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
    time_t  now;

    if (dst == NULL) {
        if (entry->lock_token == 0) {
            return sizeof("<D:lockdiscovery/>\n") - 1;
        }

        len = sizeof("<D:lockdiscovery>\n"
                     "<D:activelock>\n"
                     "<D:locktype><D:write/></D:locktype>\n"
                     "<D:lockscope><D:exclusive/></D:lockscope>\n"
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

    if (entry->lock_token == 0) {
        dst = ngx_cpymem(dst, "<D:lockdiscovery/>\n",
                         sizeof("<D:lockdiscovery/>\n") - 1);
        return (uintptr_t) dst;
    }

    now = ngx_time();

    dst = ngx_cpymem(dst, "<D:lockdiscovery>\n",
                     sizeof("<D:lockdiscovery>\n") - 1);

    dst = ngx_cpymem(dst, "<D:activelock>\n",
                     sizeof("<D:activelock>\n") - 1);

    dst = ngx_cpymem(dst, "<D:locktype><D:write/></D:locktype>\n",
                     sizeof("<D:locktype><D:write/></D:locktype>\n") - 1);

    dst = ngx_cpymem(dst, "<D:lockscope><D:exclusive/></D:lockscope>\n",
                     sizeof("<D:lockscope><D:exclusive/></D:lockscope>\n") - 1);

    dst = ngx_sprintf(dst, "<D:depth>%s</D:depth>\n",
                      entry->lock_infinite ? "infinity" : "0");

    dst = ngx_sprintf(dst, "<D:timeout>Second-%T</D:timeout>\n",
                      entry->lock_expire - now);

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

    dst = ngx_cpymem(dst, "</D:activelock>\n",
                     sizeof("</D:activelock>\n") - 1);

    dst = ngx_cpymem(dst, "</D:lockdiscovery>\n",
                     sizeof("</D:lockdiscovery>\n") - 1);

    return (uintptr_t) dst;
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

    return NGX_OK;
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
