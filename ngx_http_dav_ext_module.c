/******************************************************************************
  Copyright (c) 2012, Roman Arutyunyan (arut@qip.ru)
  All rights reserved.

  Redistribution and use in source and binary forms, with or without modification, 
  are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice, 
  this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright notice, 
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR IMPLIED
  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
  SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
  OF SUCH DAMAGE.
 *******************************************************************************/

/*

  NGINX missing WebDAV commands support

  *PROPFIND & OPTIONS*

 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <sys/types.h>
#include <dirent.h>
#include <time.h>

#include <expat.h>

#define NGX_HTTP_DAV_EXT_OFF             2

typedef struct {

	ngx_uint_t  methods;

} ngx_http_dav_ext_loc_conf_t;

static ngx_int_t ngx_http_dav_ext_init(ngx_conf_t *cf);
static void * ngx_http_dav_ext_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_dav_ext_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

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

#define NGX_HTTP_DAV_EXT_NODE_propfind           0x001
#define NGX_HTTP_DAV_EXT_NODE_prop               0x002
#define NGX_HTTP_DAV_EXT_NODE_propname           0x004
#define NGX_HTTP_DAV_EXT_NODE_allprop            0x008

#define NGX_HTTP_DAV_EXT_PROP_creationdate       0x001
#define NGX_HTTP_DAV_EXT_PROP_displayname        0x002
#define NGX_HTTP_DAV_EXT_PROP_getcontentlanguage 0x004
#define	NGX_HTTP_DAV_EXT_PROP_getcontentlength   0x008
#define NGX_HTTP_DAV_EXT_PROP_getcontenttype     0x010
#define NGX_HTTP_DAV_EXT_PROP_getetag            0x020
#define NGX_HTTP_DAV_EXT_PROP_getlastmodified    0x040
#define NGX_HTTP_DAV_EXT_PROP_lockdiscovery      0x080
#define NGX_HTTP_DAV_EXT_PROP_resourcetype       0x100
#define NGX_HTTP_DAV_EXT_PROP_source             0x200
#define NGX_HTTP_DAV_EXT_PROP_supportedlock      0x400

#define NGX_HTTP_DAV_EXT_PROPFIND_SELECTED       1
#define NGX_HTTP_DAV_EXT_PROPFIND_NAMES          2
#define NGX_HTTP_DAV_EXT_PROPFIND_ALL            3

typedef struct {

	ngx_uint_t nodes;

	ngx_uint_t props;

	ngx_uint_t propfind;

} ngx_http_dav_ext_ctx_t;

static int ngx_http_dav_ext_xmlcmp(const char *xname, const char *sname) {

	const char *c;

	c = strrchr(xname, ':');

	return strcmp(c ? c + 1 : xname, sname);
}

static void ngx_http_dav_ext_start_xml_elt(void *user_data, 
		const XML_Char *name, const XML_Char **atts)
{
	ngx_http_dav_ext_ctx_t *ctx = user_data;
		
#define NGX_HTTP_DAV_EXT_SET_NODE(nm) \
	if (!ngx_http_dav_ext_xmlcmp(name, #nm)) \
		ctx->nodes ^= NGX_HTTP_DAV_EXT_NODE_##nm

	NGX_HTTP_DAV_EXT_SET_NODE(propfind);
	NGX_HTTP_DAV_EXT_SET_NODE(prop);
	NGX_HTTP_DAV_EXT_SET_NODE(propname);
	NGX_HTTP_DAV_EXT_SET_NODE(allprop);

}

static void ngx_http_dav_ext_end_xml_elt(void *user_data, const XML_Char *name)
{
	ngx_http_dav_ext_ctx_t *ctx = user_data;

	if (ctx->nodes & NGX_HTTP_DAV_EXT_NODE_propfind) {
		
		if (ctx->nodes & NGX_HTTP_DAV_EXT_NODE_prop) {

			ctx->propfind = NGX_HTTP_DAV_EXT_PROPFIND_SELECTED;

#define NGX_HTTP_DAV_EXT_SET_PROP(nm) \
			if (!ngx_http_dav_ext_xmlcmp(name, #nm)) \
				ctx->props |= NGX_HTTP_DAV_EXT_PROP_##nm

			NGX_HTTP_DAV_EXT_SET_PROP(creationdate);
			NGX_HTTP_DAV_EXT_SET_PROP(displayname);
			NGX_HTTP_DAV_EXT_SET_PROP(getcontentlanguage);
			NGX_HTTP_DAV_EXT_SET_PROP(getcontentlength);
			NGX_HTTP_DAV_EXT_SET_PROP(getcontenttype);
			NGX_HTTP_DAV_EXT_SET_PROP(getetag);
			NGX_HTTP_DAV_EXT_SET_PROP(getlastmodified);
			NGX_HTTP_DAV_EXT_SET_PROP(lockdiscovery);
			NGX_HTTP_DAV_EXT_SET_PROP(resourcetype);
			NGX_HTTP_DAV_EXT_SET_PROP(source);
			NGX_HTTP_DAV_EXT_SET_PROP(supportedlock);

		}

		if (ctx->nodes & NGX_HTTP_DAV_EXT_NODE_propname) {

			ctx->propfind = NGX_HTTP_DAV_EXT_PROPFIND_NAMES;

		}

		if (ctx->nodes & NGX_HTTP_DAV_EXT_NODE_allprop) {

			ctx->propfind = NGX_HTTP_DAV_EXT_PROPFIND_ALL;

		}
		
	}

	ngx_http_dav_ext_start_xml_elt(user_data, name, NULL);
}

#define NGX_HTTP_DAV_EXT_COPY    0x01
#define NGX_HTTP_DAV_EXT_ESCAPE  0x02

static void
ngx_http_dav_ext_output(ngx_http_request_t *r, ngx_chain_t **ll,
	ngx_int_t flags, u_char *data, ngx_uint_t len) 
{
	ngx_chain_t *cl;
	ngx_buf_t   *b;

	if (!len) {
		return; 
	}

	if (flags & NGX_HTTP_DAV_EXT_ESCAPE) {

		b = ngx_create_temp_buf(r->pool, len + ngx_escape_html(NULL, data, len));
		b->last = (u_char*)ngx_escape_html(b->pos, data, len);

	} else if (flags & NGX_HTTP_DAV_EXT_COPY) {

		b = ngx_create_temp_buf(r->pool, len);
		b->last = ngx_cpymem(b->pos, data, len);

	} else {

		b = ngx_calloc_buf(r->pool);
		b->memory = 1;
		b->pos = data;
		b->start = data;
		b->last = b->pos + len;
		b->end = b->last;
	}

	cl = ngx_alloc_chain_link(r->pool);
	cl->buf = b;
	cl->next = NULL;

	if (*ll != NULL) {
		cl->next = (*ll)->next;
		(*ll)->next = cl;
		*ll = cl;
	} else {
		*ll = cl;
		cl->next = cl;
	}
}

static void
ngx_http_dav_ext_flush(ngx_http_request_t *r, ngx_chain_t **ll)
{
	ngx_chain_t *cl;

	cl = (*ll)->next;
	(*ll)->next = NULL;
	ngx_http_output_filter(r, cl);
	*ll = NULL;
}

/* output shortcuts

   NB: these shortcuts assume 2 variables exist in current context:
   r  - request ptr
   ll - chain ptr ptr

   output chains are buffered in circular list & flushed on demand
*/

/* output buffer copy */
#define NGX_HTTP_DAV_EXT_OUTCB(data, len) \
	ngx_http_dav_ext_output(r, ll, NGX_HTTP_DAV_EXT_COPY, (data), (len))

/* output string (no copy) */
#define NGX_HTTP_DAV_EXT_OUTS(s) \
	ngx_http_dav_ext_output(r, ll, 0, (s)->data, (s)->len)

/* output escaped string */
#define NGX_HTTP_DAV_EXT_OUTES(s) \
	ngx_http_dav_ext_output(r, ll, NGX_HTTP_DAV_EXT_ESCAPE, (s)->data, (s)->len)

/* output literal */
#define NGX_HTTP_DAV_EXT_OUTL(s) \
	ngx_http_dav_ext_output(r, ll, 0, (u_char*)(s), sizeof(s) - 1)

static ngx_int_t
ngx_http_dav_ext_send_propfind_atts(ngx_http_request_t *r, 
	char *path, ngx_str_t *uri, ngx_chain_t **ll, ngx_uint_t props)
{
	struct stat   st;
	struct tm     stm;
	u_char        buf[256];
	ngx_str_t     name;

	if (stat(path, &st)) {

		ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
				"dav_ext stat failed on '%s'", path);

		return NGX_HTTP_NOT_FOUND;
	}

	if (props & NGX_HTTP_DAV_EXT_PROP_creationdate) {

		/* output file ctime (attr change time) as creation time */
		if (gmtime_r(&st.st_ctime, &stm) == NULL)
			return NGX_ERROR;

		/* ISO 8601 time format
		   2012-02-20T16:15:00Z */
		NGX_HTTP_DAV_EXT_OUTCB(buf, strftime((char*)buf, sizeof(buf), 
						"<D:creationdate>"
							"%Y-%m-%dT%TZ"
						"</D:creationdate>\n", 

			&stm));
	}

	if (props & NGX_HTTP_DAV_EXT_PROP_displayname) {
		NGX_HTTP_DAV_EXT_OUTL(
						"<D:displayname>"
			);

		if (uri->len) {

			for(name.data = uri->data + uri->len;
				name.data >= uri->data + 1 && name.data[-1] != '/'; 
				--name.data);

			name.len = uri->data + uri->len - name.data;

			NGX_HTTP_DAV_EXT_OUTES(&name);
		}
		
		NGX_HTTP_DAV_EXT_OUTL(
						"</D:displayname>\n"
			);
	}

	if (props & NGX_HTTP_DAV_EXT_PROP_getcontentlanguage) {
		NGX_HTTP_DAV_EXT_OUTL(
						"<D:getcontentlanguage/>\n"
			);
	}

	if (props & NGX_HTTP_DAV_EXT_PROP_getcontentlength) {
		NGX_HTTP_DAV_EXT_OUTCB(buf, ngx_snprintf(buf, sizeof(buf), 
						"<D:getcontentlength>"
							"%O"
						"</D:getcontentlength>\n", 

			st.st_size) - buf);
	}
	
	if (props & NGX_HTTP_DAV_EXT_PROP_getcontenttype) {
		NGX_HTTP_DAV_EXT_OUTL(
						"<D:getcontenttype/>\n"
			);
	}

	if (props & NGX_HTTP_DAV_EXT_PROP_getetag) {
		NGX_HTTP_DAV_EXT_OUTL(
						"<D:getetag/>\n"
			);
	}

	if (props & NGX_HTTP_DAV_EXT_PROP_getlastmodified) {

		if (gmtime_r(&st.st_mtime, &stm) == NULL)
			return NGX_ERROR;

		/* RFC 2822 time format */
		NGX_HTTP_DAV_EXT_OUTCB(buf, strftime((char*)buf, sizeof(buf), 
						"<D:getlastmodified>"
							"%a, %d %b %Y %T GMT"
						"</D:getlastmodified>\n", 

			&stm));
	}

	if (props & NGX_HTTP_DAV_EXT_PROP_lockdiscovery) {
		NGX_HTTP_DAV_EXT_OUTL(
						"<D:lockdiscovery/>\n"
			);
	}

	if (props & NGX_HTTP_DAV_EXT_PROP_resourcetype) {
		if (S_ISDIR(st.st_mode)) {
			NGX_HTTP_DAV_EXT_OUTL(
						"<D:resourcetype>"
							"<D:collection/>"
						"</D:resourcetype>\n"
				);
		} else {
			NGX_HTTP_DAV_EXT_OUTL(
						"<D:resourcetype/>\n"
				);
		}
	}

	if (props & NGX_HTTP_DAV_EXT_PROP_source) {
		NGX_HTTP_DAV_EXT_OUTL(
						"<D:source/>\n"
			);
	}

	if (props & NGX_HTTP_DAV_EXT_PROP_supportedlock) {
		NGX_HTTP_DAV_EXT_OUTL(
						"<D:supportedlock/>\n"
			);
	}

	return NGX_OK;
}
				
static ngx_int_t
ngx_http_dav_ext_send_propfind_item(ngx_http_request_t *r, 
	char *path, ngx_str_t *uri)
{
	ngx_http_dav_ext_ctx_t *ctx;
	ngx_chain_t            *l = NULL, **ll = &l;
	u_char                 vbuf[8];
	ngx_str_t              status_line = ngx_string("200 OK");

	ctx = ngx_http_get_module_ctx(r, ngx_http_dav_ext_module);

	NGX_HTTP_DAV_EXT_OUTL(
			"<D:response>\n"
				"<D:href>"
		);

	NGX_HTTP_DAV_EXT_OUTES(uri);

	NGX_HTTP_DAV_EXT_OUTL(
				"</D:href>\n"
				"<D:propstat>\n"
					"<D:prop>\n"
		);

	if (ctx->propfind == NGX_HTTP_DAV_EXT_PROPFIND_NAMES) {

		NGX_HTTP_DAV_EXT_OUTL(
						"<D:creationdate/>\n"
						"<D:displayname/>\n"
						"<D:getcontentlanguage/>\n"
						"<D:getcontentlength/>\n"
						"<D:getcontenttype/>\n"
						"<D:getetag/>\n"
						"<D:getlastmodified/>\n"
						"<D:lockdiscovery/>\n"
						"<D:resourcetype/>\n"
						"<D:source/>\n"
						"<D:supportedlock/>\n"
			);

	} else {

		switch (ngx_http_dav_ext_send_propfind_atts(r, path, uri, ll,
				ctx->propfind == NGX_HTTP_DAV_EXT_PROPFIND_SELECTED ? 
				ctx->props : (ngx_uint_t)-1))
		{
			case NGX_HTTP_NOT_FOUND:
				ngx_str_set(&status_line, "404 Not Found");
				break;

			case NGX_OK:
			case NGX_HTTP_OK:
				break;

			default:
				ngx_str_set(&status_line, "500 Internal Server Error");
		}
	}

	NGX_HTTP_DAV_EXT_OUTL(
					"</D:prop>\n"
					"<D:status>HTTP/"
		);

	NGX_HTTP_DAV_EXT_OUTCB(vbuf, ngx_snprintf(vbuf, sizeof(vbuf), "%d.%d ", 
			r->http_major, r->http_minor) - vbuf);

	NGX_HTTP_DAV_EXT_OUTS(&status_line);

	NGX_HTTP_DAV_EXT_OUTL(
					"</D:status>\n"
				"</D:propstat>\n"
			"</D:response>\n"

		);

	ngx_http_dav_ext_flush(r, ll);

	return NGX_OK;
}

/* path returned by this function is terminated
   with a hidden (out-of-len) null */
static void ngx_http_dav_ext_make_child(ngx_pool_t *pool, ngx_str_t *parent, 
		u_char *child, size_t chlen, ngx_str_t *path)
{
	u_char *s;

	path->data = ngx_palloc(pool, parent->len + 2 + chlen);
	s = path->data;
	s = ngx_cpymem(s, parent->data, parent->len);
	if (parent->len > 0 && s[-1] != '/')
		*s++ = '/';
	s = ngx_cpymem(s, child, chlen);
	path->len = s - path->data;
	*s = 0;
}

#define DAV_EXT_INFINITY (-1)

static ngx_int_t
ngx_http_dav_ext_send_propfind(ngx_http_request_t *r)
{
	size_t                    root;
	ngx_str_t                 path, spath, suri;
	ngx_chain_t               *l = NULL, **ll = &l;
	DIR                       *dir;
	int                       depth;
	struct dirent             *de;
	size_t                    len;
	ngx_http_variable_value_t vv;
	ngx_str_t                 depth_name = ngx_string("depth");
	u_char                    *p;

	if (ngx_http_variable_unknown_header(&vv, &depth_name, 
					&r->headers_in.headers.part, 0) == NGX_OK
		&& vv.valid)
	{
		if (vv.len == sizeof("infinity") -1 
			&& !ngx_strncasecmp(vv.data, (u_char*)"infinity", vv.len))
		{
			depth = DAV_EXT_INFINITY; 
		} else {
			depth = ngx_atoi(vv.data, vv.len);
		}

	} else {
		depth = DAV_EXT_INFINITY;
	}

	p = ngx_http_map_uri_to_path(r, &path, &root, 0);

	if (p == NULL || !path.len) {

		ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
				"dav_ext error mapping uri to path");

		return NGX_ERROR;
	}

	path.len = p - path.data;
	*p = 0;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"http propfind path: \"%V\"", &path);

	NGX_HTTP_DAV_EXT_OUTL(
		"<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n"
		"<D:multistatus xmlns:D=\"DAV:\">\n"
		);

	ngx_http_dav_ext_flush(r, ll);

	ngx_http_dav_ext_send_propfind_item(r, (char*)path.data, &r->uri);

	if (depth) {

		/* treat infinite depth as 1 for performance reasons */

		if ((dir = opendir((char*)path.data))) {

			while((de = readdir(dir))) {

				if (!strcmp(de->d_name, ".")
					|| !strcmp(de->d_name, ".."))
				{
					continue;
				}

				len = strlen(de->d_name);

				ngx_http_dav_ext_make_child(r->pool, &path, 
					(u_char*)de->d_name, len, &spath);

				ngx_http_dav_ext_make_child(r->pool, &r->uri, 
					(u_char*)de->d_name, len, &suri);

				ngx_http_dav_ext_send_propfind_item(r, (char*)spath.data, &suri);

			}

			closedir(dir);
		}

	}

	NGX_HTTP_DAV_EXT_OUTL(
		"</D:multistatus>\n"
		);

	if (*ll && (*ll)->buf) {
		(*ll)->buf->last_buf = 1;
	}

	ngx_http_dav_ext_flush(r, ll);

	return NGX_OK;
}

static void
ngx_http_dav_ext_propfind_handler(ngx_http_request_t *r)
{
	ngx_chain_t             *c;
	ngx_buf_t               *b;
	XML_Parser              parser;
	ngx_uint_t              status;
	ngx_http_dav_ext_ctx_t *ctx;

	ctx = ngx_http_get_module_ctx(r, ngx_http_dav_ext_module);

	if (ctx == NULL) {
		ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dav_ext_ctx_t));
		ngx_http_set_ctx(r, ctx, ngx_http_dav_ext_module);
	}

	c = r->request_body->bufs;

	status = NGX_OK;

	parser = XML_ParserCreate(NULL);

	XML_SetUserData(parser, ctx);

	XML_SetElementHandler(parser, 
			ngx_http_dav_ext_start_xml_elt,
			ngx_http_dav_ext_end_xml_elt);

	for(; c != NULL && c->buf != NULL && !c->buf->last_buf; c = c->next) {

		b = c ->buf;

		if (!XML_Parse(parser, (const char*)b->pos, b->last - b->pos, b->last_buf)) {

			ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
					"dav_ext propfind XML error");

			status = NGX_ERROR;

			break;
		}

	}

	XML_ParserFree(parser);

	if (status == NGX_OK) {

		r->headers_out.status = 207;

		ngx_str_set(&r->headers_out.status_line, "207 Multi-Status");

		ngx_http_send_header(r);

		ngx_http_finalize_request(r, ngx_http_dav_ext_send_propfind(r));

	} else {

		r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;

		r->header_only = 1;

		r->headers_out.content_length_n = 0;

		ngx_http_finalize_request(r, ngx_http_send_header(r));

	}

}

static ngx_int_t
ngx_http_dav_ext_handler(ngx_http_request_t *r)
{
	ngx_int_t                    rc;
	ngx_table_elt_t              *h;
	ngx_http_dav_ext_loc_conf_t  *delcf;
		    
	delcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_ext_module);

	if (!(r->method & delcf->methods)) {
		return NGX_DECLINED;
	}

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

			/* FIXME: it looks so ugly because I cannot access nginx dav module */
			ngx_str_set(&h->key, "Allow");
			ngx_str_set(&h->value, "GET,HEAD,PUT,DELETE,MKCOL,COPY,MOVE,PROPFIND,OPTIONS");
			h->hash = 1;

			r->headers_out.status = NGX_HTTP_OK;
			r->header_only = 1;
			r->headers_out.content_length_n = 0;

			ngx_http_send_header(r);

			return NGX_OK;

	}

	return NGX_DECLINED;
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

