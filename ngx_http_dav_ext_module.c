
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <expat.h>


#define NGX_HTTP_DAV_EXT_OFF                      2

#define NGX_HTTP_DAV_EXT_PREALLOCATE              50

#define NGX_HTTP_DAV_EXT_NODE_PROPFIND            0x001
#define NGX_HTTP_DAV_EXT_NODE_PROP                0x002
#define NGX_HTTP_DAV_EXT_NODE_PROPNAME            0x004
#define NGX_HTTP_DAV_EXT_NODE_ALLPROP             0x008

#define NGX_HTTP_DAV_EXT_PROP_DISPLAYNAME         0x001
#define NGX_HTTP_DAV_EXT_PROP_GETCONTENTLENGTH    0x002
#define NGX_HTTP_DAV_EXT_PROP_GETLASTMODIFIED     0x004
#define NGX_HTTP_DAV_EXT_PROP_RESOURCETYPE        0x008
#define NGX_HTTP_DAV_EXT_PROP_LOCKDISCOVERY       0x010
#define NGX_HTTP_DAV_EXT_PROP_SUPPORTEDLOCK       0x020

#define NGX_HTTP_DAV_EXT_PROP_ALL                 0x7ff
#define NGX_HTTP_DAV_EXT_PROP_NAMES               0x800


typedef struct {
    ngx_uint_t   status;
    ngx_str_t    uri;
    ngx_str_t    name;
    ngx_uint_t   dir;  /* unsigned  dir:1; */
    time_t       mtime;
    off_t        size;
} ngx_http_dav_ext_entry_t;


typedef struct {
    ngx_uint_t   nodes;
    ngx_uint_t   props;
} ngx_http_dav_ext_ctx_t;


typedef struct {
    ngx_uint_t   methods;
} ngx_http_dav_ext_loc_conf_t;


static ngx_int_t ngx_http_dav_ext_handler(ngx_http_request_t *r);
static void ngx_http_dav_ext_propfind_handler(ngx_http_request_t *r);
static void ngx_http_dav_ext_start_xml_elt(void *user_data,
    const XML_Char *name, const XML_Char **atts);
static void ngx_http_dav_ext_end_xml_elt(void *user_data, const XML_Char *name);
static int ngx_http_dav_ext_xmlcmp(const char *xname, const char *sname);
static ngx_int_t ngx_http_dav_ext_propfind(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_ext_depth(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_ext_propfind_send_response(ngx_http_request_t *r,
    ngx_array_t *entries);
static uintptr_t ngx_http_dav_ext_format_entry(ngx_http_request_t *r,
    u_char *dst, ngx_http_dav_ext_entry_t *entry);
static void *ngx_http_dav_ext_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_dav_ext_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_dav_ext_init(ngx_conf_t *cf);


static ngx_conf_bitmask_t  ngx_http_dav_ext_methods_mask[] = {
    { ngx_string("off"),      NGX_HTTP_DAV_EXT_OFF },
    { ngx_string("propfind"), NGX_HTTP_PROPFIND    },
    { ngx_string("options"),  NGX_HTTP_OPTIONS     },
    { ngx_null_string,        0                    }
};


static ngx_command_t  ngx_http_dav_ext_commands[] = {

    { ngx_string("dav_ext_methods"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_dav_ext_loc_conf_t, methods),
      &ngx_http_dav_ext_methods_mask },

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
ngx_http_dav_ext_handler(ngx_http_request_t *r)
{
    ngx_int_t                     rc;
    ngx_table_elt_t              *h;
    ngx_http_dav_ext_loc_conf_t  *delcf;

    delcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_ext_module);

    if (!(r->method & delcf->methods)) {
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dav_ext handler");

    switch (r->method) {

    case NGX_HTTP_PROPFIND:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "dav_ext propfind");

        rc = ngx_http_read_client_request_body(r,
                                            ngx_http_dav_ext_propfind_handler);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        return NGX_DONE;

    case NGX_HTTP_OPTIONS:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "dav_ext options");

        h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_str_set(&h->key, "DAV");
        ngx_str_set(&h->value, "1");
        h->hash = 1;

        h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* XXX */
        ngx_str_set(&h->key, "Allow");
        ngx_str_set(&h->value,
                    "GET,HEAD,PUT,DELETE,MKCOL,COPY,MOVE,PROPFIND,OPTIONS");
        h->hash = 1;

        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = 0;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }

        return ngx_http_send_special(r, NGX_HTTP_LAST);
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
                          "DAV client body in file, "
                          "you may want to increase client_body_buffer_size");

            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
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
    ngx_int_t                  depth, rc;
    ngx_err_t                  err;
    ngx_str_t                  path, name, uri;
    ngx_dir_t                  dir;
    ngx_array_t                entries;
    ngx_file_info_t            fi;
    ngx_http_dav_ext_entry_t  *entry;

    if (ngx_array_init(&entries, r->pool, 40, sizeof(ngx_http_dav_ext_entry_t))
        != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_dav_ext_depth(r);
    if (rc != 0 && rc != 1) {
        return rc;
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
        last--;
    }

    *last = '\0';

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dav_ext propfind path: \"%s\"", path.data);

    if (ngx_file_info(path.data, &fi) == NGX_FILE_ERROR) {
        return NGX_HTTP_NOT_FOUND;
    }

    *last++ = '/';

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

    entry->uri = uri;
    entry->status = NGX_HTTP_OK;
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

                entry->status = NGX_HTTP_FORBIDDEN;
                continue;
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

        entry->status = NGX_HTTP_OK;
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

    /*
     * We do not support infinity depth as allowed by RFC4918:
     *
     *   In practice, support for infinite-depth requests
     *   MAY be disabled, due to the performance and security
     *   concerns associated with this behavior.
     */

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
            /*
             * RFC4918:
             *
             * 403 Forbidden -  A server MAY reject PROPFIND requests on
             * collections with depth header of "Infinity", in which case
             * it SHOULD use this error with the precondition code
             * 'propfind-finite-depth' inside the error body.
             */

            return NGX_HTTP_FORBIDDEN;
        }
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "client sent invalid \"Depth\" header: \"%V\"",
                  &depth->value);

    return NGX_HTTP_BAD_REQUEST;
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
        len += ngx_http_dav_ext_format_entry(r, NULL, &entry[n]);
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last = ngx_cpymem(b->last, head, sizeof(head) - 1);

    for (n = 0; n < entries->nelts; n++) {
        b->last = (u_char *) ngx_http_dav_ext_format_entry(r, b->last,
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

    ngx_str_set(&r->headers_out.charset, "utf-8"); /* XXX */

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &cl);
}


static uintptr_t
ngx_http_dav_ext_format_entry(ngx_http_request_t *r, u_char *dst,
    ngx_http_dav_ext_entry_t *entry)
{
    size_t                   len;
    ngx_str_t                status_line;
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

    static u_char status[] =
        "</D:prop>\n"
        "<D:status>HTTP/";

    /* major.minor status_line */

    static u_char tail[] =
        "</D:status>\n"
        "</D:propstat>\n"
        "</D:response>\n";

    static u_char names[] =
        "<D:displayname/>\n"
        "<D:getcontentlength/>\n"
        "<D:getlastmodified/>\n"
        "<D:resourcetype/>\n"
        "<D:lockdiscovery/>\n"
        "<D:supportedlock/>\n";

    ctx = ngx_http_get_module_ctx(r, ngx_http_dav_ext_module);

    switch (entry->status) {
    case NGX_HTTP_OK:
        ngx_str_set(&status_line, "200 OK");
        break;

    case NGX_HTTP_FORBIDDEN:
        ngx_str_set(&status_line, "403 Forbidden");
        break;

    default:
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (dst == NULL) {
        len = sizeof(head) - 1
              + sizeof(prop) - 1
              + sizeof(status) - 1
              + sizeof(tail) - 1;

        len += entry->uri.len + ngx_escape_html(NULL, entry->uri.data,
                                                entry->uri.len);

        len += sizeof("65536") + sizeof("65536") + status_line.len;

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

                          "<D:lockdiscovery/>\n"
                          "<D:supportedlock/>\n") - 1;

            /* displayname */
            len += entry->name.len
                   + ngx_escape_html(NULL, entry->name.data, entry->name.len);

            /* getcontentlength */
            len += NGX_OFF_T_LEN;
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
            dst = ngx_sprintf(dst, "<D:getcontentlength>%O"
                                   "</D:getcontentlength>\n", entry->size);
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
            dst = ngx_cpymem(dst, "<D:lockdiscovery/>\n",
                             sizeof("<D:lockdiscovery/>\n") - 1);
        }

        if (ctx->props & NGX_HTTP_DAV_EXT_PROP_SUPPORTEDLOCK) {
            dst = ngx_cpymem(dst, "<D:supportedlock/>\n",
                             sizeof("<D:supportedlock/>\n") - 1);
        }
    }

    dst = ngx_cpymem(dst, status, sizeof(status) - 1);
    dst = ngx_sprintf(dst, "%d.%d %V", r->http_major, r->http_major,
                      &status_line);
    dst = ngx_cpymem(dst, tail, sizeof(tail) - 1);

    return (uintptr_t) dst;
}


static void *
ngx_http_dav_ext_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_dav_ext_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dav_ext_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_http_dav_ext_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_dav_ext_loc_conf_t  *prev = parent;
    ngx_http_dav_ext_loc_conf_t  *conf = child;

    ngx_conf_merge_bitmask_value(conf->methods, prev->methods,
                         (NGX_CONF_BITMASK_SET|NGX_HTTP_DAV_EXT_OFF));

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_dav_ext_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_dav_ext_handler;

    return NGX_OK;
}
