#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <libxml/parser.h>
#include "ngx_http_dav_ext_module.h"

#define NGX_HTTP_DAV_EXT_NODE_PROPUPDATE 0x01
#define NGX_HTTP_DAV_EXT_NODE_SET_REMOVE 0x02
#define NGX_HTTP_DAV_EXT_NODE_PROP       0x04
#define NGX_HTTP_DAV_EXT_PROP            0x08

#define INIT_PROP_COUNT 20


typedef struct {
    const xmlChar *prefix;
    const xmlChar *name;
    const xmlChar *value;
    int     value_len;
} ngx_http_dav_ext_propatch_property_t;

typedef struct {
    const xmlChar* prefix;
    const xmlChar* namespace;
} ngx_http_dav_ext_propatch_namespace_t;

typedef struct {
    ngx_int_t                          nodes;
    ngx_http_dav_ext_propatch_property_t *current_property;
    ngx_array_t                        *properties;
    ngx_http_request_t                 *request;
    ngx_array_t                        *namespaces;
} ngx_http_dav_ext_propatch_xml_ctx_t;

static void ngx_http_dav_ext_proppatch_xml_start(void *data,
    const xmlChar *localname, const xmlChar *prefix, const xmlChar *uri,
    int nb_namespaces, const xmlChar **namespaces, int nb_attributes,
    int nb_defaulted, const xmlChar **attributes);
static void ngx_http_dav_ext_proppatch_xml_end(void *data,
    const xmlChar *localname, const xmlChar *prefix, const xmlChar *uri);
static ngx_int_t ngx_http_dav_ext_proppatch(ngx_http_request_t *r,
    char* propstats);
static void ngx_http_dav_ext_proppatch_add_namespace ( ngx_array_t *namespaces,
    const xmlChar *prefix, const xmlChar *namespace );
static void ngx_http_dav_ext_proppatch_invert_node( ngx_http_dav_ext_propatch_xml_ctx_t *xctx,
    const xmlChar* namespacae, const xmlChar* fieldname, const xmlChar * namespace );
static void ngx_http_dav_ext_proppatch_parse_property( void *data,
    const xmlChar* content , int len);
static char *ngx_http_dav_ext_proppatch_create_propstats(ngx_http_request_t *r,
    ngx_array_t* properties, ngx_array_t* namespaces);

void ngx_http_dav_ext_proppatch_handler(ngx_http_request_t *r)
{
    off_t                                 len;
    ngx_buf_t                            *b;
    ngx_chain_t                          *cl;
    xmlSAXHandler                         sax;
    xmlParserCtxtPtr                      pctx;
    ngx_http_dav_ext_propatch_xml_ctx_t   xctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http dav_ext proppatch handler");

    ngx_memzero(&xctx, sizeof(ngx_http_dav_ext_propatch_xml_ctx_t));
    xctx.properties = ngx_array_create(r->pool,INIT_PROP_COUNT*2,
                      sizeof(ngx_http_dav_ext_propatch_property_t));
    xctx.namespaces = ngx_array_create(r->pool,3,
                      sizeof(ngx_http_dav_ext_propatch_namespace_t));
    xctx.request = r;

    ngx_memzero(&sax, sizeof(xmlSAXHandler));
    sax.initialized = XML_SAX2_MAGIC;
    sax.startElementNs = ngx_http_dav_ext_proppatch_xml_start;
    sax.endElementNs = ngx_http_dav_ext_proppatch_xml_end;
    sax.characters = ngx_http_dav_ext_proppatch_parse_property;

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
                          b->last_buf)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "xmlParseChunk() failed");
            xmlFreeParserCtxt(pctx);
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            return;
        }
    }

    char *propstats = ngx_http_dav_ext_proppatch_create_propstats(r,
                                           xctx.properties, xctx.namespaces );

    ngx_array_destroy(xctx.properties);
    xmlFreeParserCtxt(pctx);

    ngx_http_finalize_request(r, ngx_http_dav_ext_proppatch(r, propstats));
}

void  ngx_http_dav_ext_proppatch_add_namespace ( ngx_array_t *namespaces,
                        const xmlChar* prefix, const xmlChar* namespace )
{
    ngx_http_dav_ext_propatch_namespace_t *namespace_array= namespaces->elts;

    unsigned int i;
    for (i = 0; i < namespaces->nelts; i++) {
        ngx_http_dav_ext_propatch_namespace_t* nsp = &namespace_array[i];
        if (strcmp((char*)nsp->prefix, (char*)prefix) == 0
           && strcmp((char*)nsp->namespace, (char*)namespace) == 0 ) {
            break;
        }
    }

    if ( i == namespaces->nelts ) {
        ngx_http_dav_ext_propatch_namespace_t* nsp =ngx_array_push(namespaces);
        nsp->prefix=prefix;
        nsp->namespace=namespace;
    }
}

void ngx_http_dav_ext_proppatch_invert_node(
                            ngx_http_dav_ext_propatch_xml_ctx_t *xctx,
                            const xmlChar* prefix,
                            const xmlChar* fieldname,
                            const xmlChar* namespace )
{
    ngx_http_dav_ext_proppatch_add_namespace ( xctx->namespaces, prefix, namespace );
    if ( (xctx->nodes & NGX_HTTP_DAV_EXT_PROP) && ngx_strcmp(xctx->current_property->name,fieldname) != 0 ) {
        return;
    }
    if ( xctx->nodes & NGX_HTTP_DAV_EXT_NODE_PROP && ngx_strcmp(fieldname, "prop") != 0 ) {
      if ( (xctx->nodes & NGX_HTTP_DAV_EXT_PROP) == 0 ) {
        xctx->current_property = ngx_array_push(xctx->properties );
        xctx->current_property->name = fieldname;
        xctx->current_property->prefix = prefix;
        xctx->current_property->value = NULL;
        xctx->current_property->value_len = 0;
      }
      xctx->nodes ^= NGX_HTTP_DAV_EXT_PROP;
    }
    if ( xctx->nodes & NGX_HTTP_DAV_EXT_NODE_SET_REMOVE ) {
      if ( ngx_strcmp(fieldname, "prop") == 0 ){
        xctx->nodes ^= NGX_HTTP_DAV_EXT_NODE_PROP;
      }
    }
    if ( xctx->nodes & NGX_HTTP_DAV_EXT_NODE_PROPUPDATE ) {
      if (ngx_strcmp(fieldname, "set") == 0) {
          xctx->nodes ^= NGX_HTTP_DAV_EXT_NODE_SET_REMOVE;
      }
      else if (ngx_strcmp(fieldname, "remove") == 0) {
          xctx->nodes ^= NGX_HTTP_DAV_EXT_NODE_SET_REMOVE;
      }
    }
    if ( xctx->nodes == 0 ) {
      if (ngx_strcmp(fieldname, "propertyupdate") == 0) {
          xctx->nodes ^= NGX_HTTP_DAV_EXT_NODE_PROPUPDATE;
      }
    }
}

void
ngx_http_dav_ext_proppatch_xml_start(void *data, const xmlChar *localname,
    const xmlChar *prefix, const xmlChar *uri, int nb_namespaces,
    const xmlChar **namespaces, int nb_attributes, int nb_defaulted,
    const xmlChar **attributes)
{
    ngx_http_dav_ext_propatch_xml_ctx_t *xctx = data;
    ngx_http_dav_ext_proppatch_invert_node ( xctx, prefix, localname, uri );
}

void ngx_http_dav_ext_proppatch_parse_property( void *data,
    const xmlChar* content , int len)
{
    ngx_http_dav_ext_propatch_xml_ctx_t *xctx = data;
    xctx->current_property->value = content;
    xctx->current_property->value_len = len;
}

void
ngx_http_dav_ext_proppatch_xml_end(void *data, const xmlChar *localname,
    const xmlChar *prefix, const xmlChar *uri)
{
    ngx_http_dav_ext_propatch_xml_ctx_t *xctx = data;
    ngx_http_dav_ext_proppatch_invert_node ( xctx, prefix, localname, uri );
}


char*
ngx_http_dav_ext_proppatch_create_propstats(ngx_http_request_t *r,
    ngx_array_t *properties, ngx_array_t *namespaces)
{
    ngx_http_dav_ext_propatch_property_t* props = properties->elts;
    ngx_http_dav_ext_propatch_namespace_t* namesps = namespaces->elts;

    static u_char multi_head[] =
        "<?xml version=\"1.0\" encoding=\"utf-8\" ?>"
        "<D:multistatus";

    static u_char xlmns[] =
        " xmlns:";

    static u_char nsp_assign[] =
        "=\"";

    static u_char xmlns_end[] =
        "\"";

    static u_char multi_head_end[] =
        ">";

    static u_char multi_tail[] =
        "</D:multistatus>";

    static u_char head[] =
        "<D:response>"
        "<D:href>";

    static u_char head_end[] =
        "</D:href>";

    static u_char propstat[] =
        "<D:propstat>"
        "<D:prop><";

    static u_char propstat_end[] =
        "/></D:prop>"
        "<D:status>HTTP/1.1 403 Forbidden</D:status>"
        "</D:propstat>";

    static u_char tail[] =
        "</D:response>";

    ngx_int_t size = ngx_strlen(multi_head)
                + ngx_strlen(multi_head)
                + ngx_strlen(multi_head_end)
                + ngx_strlen(head)
                + r->uri.len
                + ngx_strlen(head_end)
                + ngx_strlen(tail)
                + ngx_strlen(multi_tail)
                + 1;

   for (unsigned int i = 0; i< namespaces->nelts; i++) {
     ngx_http_dav_ext_propatch_namespace_t *nsp = &namesps[i];
     size += ngx_strlen(xlmns)
           + ngx_strlen(nsp->prefix)
           + ngx_strlen(nsp_assign)
           + ngx_strlen(nsp->namespace)
           + ngx_strlen(xmlns_end);
   }

   for (unsigned int i = 0; i< properties->nelts; i++) {
     ngx_http_dav_ext_propatch_property_t *prop = &props[i];
     size += ngx_strlen(propstat)
           + ngx_strlen(prop->prefix)
           + 1
           + ngx_strlen(prop->name)
           + ngx_strlen(propstat_end);
   }

   char* buffer = ngx_pnalloc(r->pool,size);
   void* dst = buffer;

   dst = ngx_copy(dst,multi_head, ngx_strlen(multi_head));
   for (unsigned int i = 0; i< namespaces->nelts; i++) {
     ngx_http_dav_ext_propatch_namespace_t *nsp = &namesps[i];
     dst = ngx_copy(dst, xlmns, ngx_strlen(xlmns));
     dst = ngx_copy(dst, nsp->prefix, ngx_strlen(nsp->prefix));
     dst = ngx_copy(dst, nsp_assign, ngx_strlen(nsp_assign));
     dst = ngx_copy(dst, nsp->namespace, ngx_strlen(nsp->namespace));
     dst = ngx_copy(dst, xmlns_end, ngx_strlen(xmlns_end));
   }

   dst = ngx_copy(dst,multi_head_end, ngx_strlen(multi_head_end));
   dst = ngx_copy(dst,head, ngx_strlen(head));
   dst = ngx_copy(dst,r->uri.data, r->uri.len);
   dst = ngx_copy(dst,head_end, ngx_strlen(head_end));

   for (unsigned int i = 0 ; i < properties->nelts; i++) {
     ngx_http_dav_ext_propatch_property_t *prop = &props[i];
     dst = ngx_copy(dst,propstat, ngx_strlen(propstat));
     dst = ngx_copy(dst,prop->prefix, ngx_strlen(prop->prefix));
     dst = ngx_copy(dst,":", 1);
     dst = ngx_copy(dst,prop->name, ngx_strlen(prop->name));
     dst = ngx_copy(dst,propstat_end, ngx_strlen(propstat_end));
   }

   dst = ngx_copy(dst,tail, ngx_strlen(tail));
   dst = ngx_copy(dst,multi_tail, ngx_strlen(multi_tail));
   dst = ngx_copy(dst,"\0", 1);
   return buffer;
}

ngx_int_t
ngx_http_dav_ext_proppatch(ngx_http_request_t *r, char* response)
{
    ngx_buf_t                 *b;
    ngx_int_t                  rc;
    ngx_chain_t                cl;

    b = ngx_create_temp_buf(r->pool, ngx_strlen(response));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last = ngx_cpymem(b->last, response, strlen(response));

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    ngx_pfree(r->pool,response);

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
