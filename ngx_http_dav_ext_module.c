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

  PROPFIND OPTIONS LOCK UNLOCK
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <sys/types.h>
#include <dirent.h>
#include <time.h>
#include <expat.h>


#define NGX_HTTP_DAV_EXT_LOCK_ZONE  "dav-ext-zone"
#define NGX_HTTP_DAV_EXT_LOCK_SIZE  65536


typedef struct {
    ngx_rbtree_node_t               node;
    ngx_str_t                       path;
    ngx_int_t                       depth;
    ngx_str_t                       user;
    time_t                          expire;
    ngx_str_t                       token;
} ngx_http_dav_ext_lock_t;


typedef struct {
    ngx_rbtree_t                    rbtree;
    ngx_rbtree_node_t               sentinel;
} ngx_http_dav_ext_cache_sh_t;


typedef struct {
    ngx_http_dav_ext_cache_sh_t    *sh;
    ngx_slab_pool_t                *shpool;
    ngx_shm_zone_t                 *shm_zone;
} ngx_http_dav_ext_cache_t;


typedef struct {
    ngx_uint_t                      methods;
    ngx_log_t                      *log;
    ngx_http_dav_ext_cache_t       *cache;
} ngx_http_dav_ext_loc_conf_t;


typedef struct {
    ngx_int_t                       depth;
    /*TODO: If, Lock-Token */

    ngx_uint_t                      nodes;
    ngx_uint_t                      props;
    ngx_uint_t                      propfind;

    ngx_uint_t                      lock_scope;
    ngx_uint_t                      lock_type;
    ngx_str_t                       lock_owner;
} ngx_http_dav_ext_ctx_t;


static ngx_http_dav_ext_lock_t *
    ngx_http_dav_ext_get_lock(ngx_http_dav_ext_cache_t *cache, 
    ngx_str_t *path);
static void ngx_http_dav_ext_rbtree_insert_lock(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static void ngx_http_dav_ext_delete_lock(ngx_http_dav_ext_cache_t *cache,
    ngx_http_dav_ext_lock_t *lock);
static ngx_int_t ngx_http_dav_ext_add_lock(ngx_http_dav_ext_cache_t *cache,
    ngx_http_dav_ext_lock_t *lock);


#define NGX_HTTP_DAV_EXT_NODE_propfind              0x0001
#define NGX_HTTP_DAV_EXT_NODE_prop                  0x0002
#define NGX_HTTP_DAV_EXT_NODE_propname              0x0004
#define NGX_HTTP_DAV_EXT_NODE_allprop               0x0008
#define NGX_HTTP_DAV_EXT_NODE_lockinfo              0x0010
#define NGX_HTTP_DAV_EXT_NODE_lockscope             0x0020
#define NGX_HTTP_DAV_EXT_NODE_locktype              0x0040
#define NGX_HTTP_DAV_EXT_NODE_owner                 0x0080
#define NGX_HTTP_DAV_EXT_NODE_href                  0x0100
#define NGX_HTTP_DAV_EXT_NODE_exclusive             0x0200
#define NGX_HTTP_DAV_EXT_NODE_write                 0x0400

#define NGX_HTTP_DAV_EXT_PROP_creationdate          0x0001
#define NGX_HTTP_DAV_EXT_PROP_displayname           0x0002
#define NGX_HTTP_DAV_EXT_PROP_getcontentlanguage    0x0004
#define	NGX_HTTP_DAV_EXT_PROP_getcontentlength      0x0008
#define NGX_HTTP_DAV_EXT_PROP_getcontenttype        0x0010
#define NGX_HTTP_DAV_EXT_PROP_getetag               0x0020
#define NGX_HTTP_DAV_EXT_PROP_getlastmodified       0x0040
#define NGX_HTTP_DAV_EXT_PROP_lockdiscovery         0x0080
#define NGX_HTTP_DAV_EXT_PROP_resourcetype          0x0100
#define NGX_HTTP_DAV_EXT_PROP_source                0x0200
#define NGX_HTTP_DAV_EXT_PROP_supportedlock         0x0400

#define NGX_HTTP_DAV_EXT_PROPFIND_SELECTED          1
#define NGX_HTTP_DAV_EXT_PROPFIND_NAMES             2
#define NGX_HTTP_DAV_EXT_PROPFIND_ALL               3

#define NGX_HTTP_DAV_EXT_EXCLUSIVE                  1
#define NGX_HTTP_DAV_EXT_WRITE                      1

#define NGX_HTTP_DAV_EXT_TIMEOUT                    300

#define NGX_HTTP_DAV_EXT_OFF                        2


static ngx_int_t ngx_http_dav_ext_init(ngx_conf_t *cf);
static void * ngx_http_dav_ext_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_dav_ext_merge_loc_conf(ngx_conf_t *cf, 
        void *parent, void *child);


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


static void
ngx_http_dav_ext_delete_lock(ngx_http_dav_ext_cache_t *cache, 
    ngx_http_dav_ext_lock_t *lock)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "dav_ext: deleting lock for '%V'", &lock->path);

    ngx_shmtx_lock(&cache->shpool->mutex);

    ngx_rbtree_delete(&cache->sh->rbtree, &lock->node);
    ngx_slab_free_locked(cache->shpool, lock);

    ngx_shmtx_unlock(&cache->shpool->mutex);
}


static ngx_int_t
ngx_http_dav_ext_add_lock(ngx_http_dav_ext_cache_t *cache,
    ngx_http_dav_ext_lock_t *lock)
{
    ngx_http_dav_ext_lock_t        *lck;
    u_char                         *p;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "dav_ext: adding lock for '%V'", &lock->path);

    ngx_shmtx_lock(&cache->shpool->mutex);

    lck = ngx_http_dav_ext_get_lock(cache, &lock->path);

    if (lck == NULL) {

        lck = ngx_slab_alloc_locked(cache->shpool,
                                    sizeof(ngx_http_dav_ext_lock_t)
                                    + lock->path.len + lock->user.len 
                                    + lock->token.len);
        if (lock == NULL) {
            ngx_shmtx_unlock(&cache->shpool->mutex);
            return NGX_ERROR;
        }

        *lck = *lock;
        lck->node.key = ngx_hash_key(lock->path.data, lock->path.len);

        p = (u_char *) lck + sizeof(ngx_http_dav_ext_lock_t);

        lck->path.data = p;
        p = ngx_cpymem(p, lock->path.data, lock->path.len);
        
        lck->user.data = p;
        p = ngx_cpymem(p, lock->user.data, lock->user.len);

        lck->token.data = p;
        ngx_memcpy(p, lock->token.data, lock->token.len);

        ngx_rbtree_insert(&cache->sh->rbtree, &lock->node);
    }

    ngx_shmtx_unlock(&cache->shpool->mutex);

    return NGX_OK;
}


static ngx_http_dav_ext_lock_t *
ngx_http_dav_ext_get_lock(ngx_http_dav_ext_cache_t *cache, ngx_str_t *path)
{
    ngx_int_t                   rc;
    ngx_rbtree_key_t            node_key;
    ngx_rbtree_node_t          *node, *sentinel;
    ngx_http_dav_ext_lock_t    *lck;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "dav_ext: looking up lock for path '%V'", path);

    node_key = ngx_hash_key(path->data, path->len);

    node = cache->sh->rbtree.root;
    sentinel = cache->sh->rbtree.sentinel;

    while (node != sentinel) {

        if (node_key < node->key) {
            node = node->left;
            continue;
        }

        if (node_key > node->key) {
            node = node->right;
            continue;
        }

        /* node_key == node->key */

        lck = (ngx_http_dav_ext_lock_t *) node;

        if (lck->path.len != path->len) {
            node = (lck->path.len < path->len) ? node->left : node->right;
            continue;
        }

        rc = ngx_memcmp(lck->path.data, path->data, path->len);

        if (rc == 0) {
            return lck;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* not found */

    return NULL;
}


static void
ngx_http_dav_ext_rbtree_insert_lock(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t         **p;
    ngx_http_dav_ext_lock_t    *cn, *cnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            cn = (ngx_http_dav_ext_lock_t *) node;
            cnt = (ngx_http_dav_ext_lock_t *) temp;

            p = (cn->path.len < cnt->path.len ||
                (cn->path.len == cnt->path.len && 
                    ngx_memcmp(cn->path.data, cnt->path.data, cn->path.len)
                < 0))
                   ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_int_t
ngx_http_dav_ext_locks_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_dav_ext_cache_t   *ocache = data;

    size_t                      len;
    ngx_http_dav_ext_cache_t   *cache;

    cache = shm_zone->data;

    if (ocache) {
        cache->sh = ocache->sh;
        cache->shpool = ocache->shpool;
        return NGX_OK;
    }

    cache->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        cache->sh = cache->shpool->data;
        return NGX_OK;
    }

    cache->sh = ngx_slab_alloc(cache->shpool, 
                               sizeof(ngx_http_dav_ext_cache_sh_t));
    if (cache->sh == NULL) {
        return NGX_ERROR;
    }

    cache->shpool->data = cache->sh;

    ngx_rbtree_init(&cache->sh->rbtree, &cache->sh->sentinel,
                    ngx_http_dav_ext_rbtree_insert_lock);

    len = sizeof(" in dav lock zone \"\"") + shm_zone->shm.name.len;

    cache->shpool->log_ctx = ngx_slab_alloc(cache->shpool, len);
    if (cache->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(cache->shpool->log_ctx, " in dav lock zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}


static int 
ngx_http_dav_ext_xmlcmp(const char *xname, const char *sname) 
{
    const char *c;

    c = strrchr(xname, ':');
    return strcmp(c ? c + 1 : xname, sname);
}


static void 
ngx_http_dav_ext_start_xml_elt(void *user_data, const XML_Char *name, 
        const XML_Char **atts)
{
    ngx_http_request_t         *r = user_data;
    ngx_http_dav_ext_ctx_t     *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_dav_ext_module);

#define NGX_HTTP_DAV_EXT_SET_NODE(nm)                           \
    if (!ngx_http_dav_ext_xmlcmp(name, #nm)) {                  \
        ctx->nodes ^= NGX_HTTP_DAV_EXT_NODE_##nm;               \
    }

    NGX_HTTP_DAV_EXT_SET_NODE(propfind);
    NGX_HTTP_DAV_EXT_SET_NODE(prop);
    NGX_HTTP_DAV_EXT_SET_NODE(propname);
    NGX_HTTP_DAV_EXT_SET_NODE(allprop);
    NGX_HTTP_DAV_EXT_SET_NODE(lockinfo);
    NGX_HTTP_DAV_EXT_SET_NODE(lockscope);
    NGX_HTTP_DAV_EXT_SET_NODE(locktype);
    NGX_HTTP_DAV_EXT_SET_NODE(owner);
    NGX_HTTP_DAV_EXT_SET_NODE(href);
    NGX_HTTP_DAV_EXT_SET_NODE(exclusive);
    NGX_HTTP_DAV_EXT_SET_NODE(write);

#undef NGX_HTTP_DAV_EXT_SET_NODE
}


static void
ngx_http_dav_ext_end_xml_elt(void *user_data, const XML_Char *name)
{
    ngx_http_request_t         *r = user_data;
    ngx_http_dav_ext_ctx_t     *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_dav_ext_module);

    if (ctx->nodes & NGX_HTTP_DAV_EXT_NODE_propfind) {
        if (ctx->nodes & NGX_HTTP_DAV_EXT_NODE_prop) {
            ctx->propfind = NGX_HTTP_DAV_EXT_PROPFIND_SELECTED;

#define NGX_HTTP_DAV_EXT_SET_PROP(nm)                           \
            if (!ngx_http_dav_ext_xmlcmp(name, #nm)) {          \
                ctx->props |= NGX_HTTP_DAV_EXT_PROP_##nm;       \
            }

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

#undef NGX_HTTP_DAV_EXT_SET_PROP
        }

        if (ctx->nodes & NGX_HTTP_DAV_EXT_NODE_propname) {
            ctx->propfind = NGX_HTTP_DAV_EXT_PROPFIND_NAMES;
        }

        if (ctx->nodes & NGX_HTTP_DAV_EXT_NODE_allprop) {
            ctx->propfind = NGX_HTTP_DAV_EXT_PROPFIND_ALL;
        }
    }

    if (ctx->nodes & NGX_HTTP_DAV_EXT_NODE_lockinfo) {
        if (ctx->nodes & NGX_HTTP_DAV_EXT_NODE_lockscope
                && ctx->nodes & NGX_HTTP_DAV_EXT_NODE_exclusive)
        {
            ctx->lock_scope = NGX_HTTP_DAV_EXT_EXCLUSIVE;
        }

        if (ctx->nodes & NGX_HTTP_DAV_EXT_NODE_locktype
                && ctx->nodes & NGX_HTTP_DAV_EXT_NODE_write)
        {
            ctx->lock_type = NGX_HTTP_DAV_EXT_WRITE;
        }
    }

    ngx_http_dav_ext_start_xml_elt(user_data, name, NULL);
}


static void
ngx_http_dav_ext_xml_data(void *user_data, const XML_Char *s, int len)
{
    ngx_http_request_t         *r = user_data;
	ngx_http_dav_ext_ctx_t     *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_dav_ext_module);

	if (ctx->nodes & NGX_HTTP_DAV_EXT_NODE_lockinfo
        && ctx->nodes & NGX_HTTP_DAV_EXT_NODE_owner
        && ctx->nodes & NGX_HTTP_DAV_EXT_NODE_href)
    {
        ctx->lock_owner.data = ngx_palloc(r->pool, len);
        if (ctx->lock_owner.data == NULL) {
            return;
        }
        ctx->lock_owner.len = len;
        ngx_memcpy(ctx->lock_owner.data, s, len);
    }
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


static void
ngx_http_dav_ext_send_lockdiscovery(ngx_http_request_t *r, 
        ngx_http_dav_ext_lock_t *lck, ngx_chain_t **ll)
{
    u_char                          buf[NGX_OFF_T_LEN + 1];

    NGX_HTTP_DAV_EXT_OUTL(
                "<D:lockdiscovery>"
                    "<D:activelock>"
                        "<D:locktype>"
                            "<D:write/>"
                        "</D:locktype>"
                        "<D:lockscope>"
                            "<D:exclusive/>"
                        "</D:lockscope>"
                        "<D:depth>"
            );

    if (lck->depth == -1) {
        NGX_HTTP_DAV_EXT_OUTL("Infinity");
    } else {
        NGX_HTTP_DAV_EXT_OUTL("0");
    }

    NGX_HTTP_DAV_EXT_OUTL(
                        "</D:depth>"
                        "<D:owner>"
                            "<D:href>"
            );

    if (lck->user.len) {
        NGX_HTTP_DAV_EXT_OUTES(&lck->user);
    }

    NGX_HTTP_DAV_EXT_OUTL(
                            "</D:href>"
                        "</D:owner>"
                        "<D:timeout>"
            );

    if (lck->expire == 0) {
        NGX_HTTP_DAV_EXT_OUTL("Infinite");
    } else {
        NGX_HTTP_DAV_EXT_OUTL("Second-");
        NGX_HTTP_DAV_EXT_OUTCB(buf, ngx_snprintf(buf, sizeof(buf), "%i", 
                    lck->expire - ngx_cached_time->sec) - buf);
    }

    NGX_HTTP_DAV_EXT_OUTL(
                        "</D:timeout>"
                        "<D:locktoken>"
                            "<D:href>"
            );

    NGX_HTTP_DAV_EXT_OUTES(&lck->token);

    NGX_HTTP_DAV_EXT_OUTL(
                            "</D:href>"
                        "</D:locktoken>"
                    "</D:activelock>"
                "</D:lockdiscovery>"
            );
}


static ngx_int_t
ngx_http_dav_ext_send_propfind_atts(ngx_http_request_t *r, 
	u_char *path, ngx_str_t *uri, ngx_chain_t **ll, ngx_uint_t props)
{
    struct stat                         st;
    struct tm                           stm;
    u_char                              buf[256];
    ngx_str_t                           name;
    ngx_http_dav_ext_loc_conf_t        *dlcf;
    ngx_http_dav_ext_lock_t            *lck;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_ext_module);

    if (stat((char *)path, &st)) {
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
                    "</D:creationdate>",
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
                    "</D:displayname>"
                );
    }

    if (props & NGX_HTTP_DAV_EXT_PROP_getcontentlanguage) {
        NGX_HTTP_DAV_EXT_OUTL(
                    "<D:getcontentlanguage/>"
                );
    }

    if (props & NGX_HTTP_DAV_EXT_PROP_getcontentlength) {
        NGX_HTTP_DAV_EXT_OUTCB(buf, ngx_snprintf(buf, sizeof(buf), 
                    "<D:getcontentlength>"
                        "%O"
                    "</D:getcontentlength>", 
                    st.st_size) - buf);
    }

    if (props & NGX_HTTP_DAV_EXT_PROP_getcontenttype) {
        NGX_HTTP_DAV_EXT_OUTL(
                    "<D:getcontenttype/>"
                );
    }

    if (props & NGX_HTTP_DAV_EXT_PROP_getetag) {
        NGX_HTTP_DAV_EXT_OUTL(
                    "<D:getetag/>"
                );
    }

    if (props & NGX_HTTP_DAV_EXT_PROP_getlastmodified) {
        if (gmtime_r(&st.st_mtime, &stm) == NULL)
            return NGX_ERROR;

        /* RFC 2822 time format */
        NGX_HTTP_DAV_EXT_OUTCB(buf, strftime((char*)buf, sizeof(buf), 
                    "<D:getlastmodified>"
                        "%a, %d %b %Y %T GMT"
                    "</D:getlastmodified>",
                    &stm));
    }

    if (props & NGX_HTTP_DAV_EXT_PROP_lockdiscovery
            && dlcf->methods & NGX_HTTP_LOCK)
    {
        lck = ngx_http_dav_ext_get_lock(dlcf->cache, uri);
        if (lck) {
            ngx_http_dav_ext_send_lockdiscovery(r, lck, ll);
        }
    }

    if (props & NGX_HTTP_DAV_EXT_PROP_resourcetype) {
        if (S_ISDIR(st.st_mode)) {
            NGX_HTTP_DAV_EXT_OUTL(
                    "<D:resourcetype>"
                        "<D:collection/>"
                    "</D:resourcetype>"
                    );
        } else {
            NGX_HTTP_DAV_EXT_OUTL(
                    "<D:resourcetype/>"
                    );
        }
    }

    if (props & NGX_HTTP_DAV_EXT_PROP_source) {
        NGX_HTTP_DAV_EXT_OUTL(
                    "<D:source/>"
                );
    }

    if (props & NGX_HTTP_DAV_EXT_PROP_supportedlock
            && dlcf->methods & NGX_HTTP_LOCK) 
    {
        NGX_HTTP_DAV_EXT_OUTL(
                    "<D:supportedlock>"
                        "<D:lockentry>"
                            "<D:lockscope>"
                                "<D:exclusive/>"
                            "</D:lockscope>"
                            "<D:locktype>"
                                "<D:write/>"
                            "</D:locktype>"
                        "</D:lockentry>"
                    "</D:supportedlock>"
                );
    }

    return NGX_OK;
}

				
static ngx_int_t
ngx_http_dav_ext_send_propfind_item(ngx_http_request_t *r, 
	u_char *path, ngx_str_t *uri)
{
    ngx_http_dav_ext_ctx_t         *ctx;
    ngx_chain_t                    *l = NULL, **ll = &l;
    u_char                          vbuf[8];
    ngx_str_t                       status_line = ngx_string("200 OK");

    ctx = ngx_http_get_module_ctx(r, ngx_http_dav_ext_module);

    NGX_HTTP_DAV_EXT_OUTL(
            "<D:response>"
                "<D:href>"
            );

    NGX_HTTP_DAV_EXT_OUTES(uri);

    NGX_HTTP_DAV_EXT_OUTL(
                "</D:href>"
                "<D:propstat>"
                    "<D:prop>\n"
            );

    if (ctx->propfind == NGX_HTTP_DAV_EXT_PROPFIND_NAMES) {
        NGX_HTTP_DAV_EXT_OUTL(
                        "<D:creationdate/>"
                        "<D:displayname/>"
                        "<D:getcontentlanguage/>"
                        "<D:getcontentlength/>"
                        "<D:getcontenttype/>"
                        "<D:getetag/>"
                        "<D:getlastmodified/>"
                        "<D:lockdiscovery/>"
                        "<D:resourcetype/>"
                        "<D:source/>"
                        "<D:supportedlock/>"
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
                    "</D:prop>"
                    "<D:status>HTTP/"
            );

    NGX_HTTP_DAV_EXT_OUTCB(vbuf, ngx_snprintf(vbuf, sizeof(vbuf), "%d.%d ", 
                r->http_major, r->http_minor) - vbuf);

    NGX_HTTP_DAV_EXT_OUTS(&status_line);

    NGX_HTTP_DAV_EXT_OUTL(
                    "</D:status>"
                "</D:propstat>"
            "</D:response>"
            );

    ngx_http_dav_ext_flush(r, ll);

    return NGX_OK;
}


/* path returned by this function is terminated
   with a hidden (out-of-len) null */
static void 
ngx_http_dav_ext_make_child(ngx_pool_t *pool, ngx_str_t *parent, 
		u_char *child, size_t chlen, ngx_str_t *path)
{
    u_char         *s;

    path->data = ngx_palloc(pool, parent->len + 2 + chlen);
    s = path->data;
    s = ngx_cpymem(s, parent->data, parent->len);
    if (parent->len > 0 && s[-1] != '/')
        *s++ = '/';
    s = ngx_cpymem(s, child, chlen);
    path->len = s - path->data;
    *s = 0;
}


static ngx_int_t
ngx_http_dav_ext_send_propfind(ngx_http_request_t *r)
{
    size_t                          root;
    ngx_str_t                       path, spath, suri;
    ngx_chain_t                    *l = NULL, **ll = &l;
    DIR                            *dir;
    struct dirent                  *de;
    size_t                          len;
    u_char                         *p;
    ngx_http_dav_ext_ctx_t         *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_dav_ext_module);

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
        "<D:multistatus xmlns:D=\"DAV:\">"
        );

    ngx_http_dav_ext_flush(r, ll);
    ngx_http_dav_ext_send_propfind_item(r, path.data, &r->uri);

    /* treat infinite depth as 1 for performance reasons */
    if (ctx->depth) {
        if ((dir = opendir((char*)path.data))) {
            while((de = readdir(dir))) {
                if (!ngx_strcmp(de->d_name, ".")
                        || !ngx_strcmp(de->d_name, ".."))
                {
                    continue;
                }
                len = ngx_strlen(de->d_name);

                ngx_http_dav_ext_make_child(r->pool, &path, 
                        (u_char *)de->d_name, len, &spath);

                ngx_http_dav_ext_make_child(r->pool, &r->uri, 
                        (u_char *)de->d_name, len, &suri);

                ngx_http_dav_ext_send_propfind_item(r, spath.data, &suri);
            }

            closedir(dir);
        }

    }

    NGX_HTTP_DAV_EXT_OUTL(
        "</D:multistatus>"
        );

    if (*ll && (*ll)->buf) {
        (*ll)->buf->last_buf = 1;
    }

    ngx_http_dav_ext_flush(r, ll);

    return NGX_OK;
}


static ngx_int_t
ngx_http_dav_ext_send_lock(ngx_http_request_t *r, 
        ngx_http_dav_ext_lock_t *lck)
{
    ngx_chain_t                    *l = NULL, **ll = &l;

    NGX_HTTP_DAV_EXT_OUTL(
        "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n"
        "<D:prop xmlns:D=\"DAV:\">"
        );

    ngx_http_dav_ext_send_lockdiscovery(r, lck, ll);

    NGX_HTTP_DAV_EXT_OUTL(
        "</D:prop>"
        );

    if (*ll && (*ll)->buf) {
        (*ll)->buf->last_buf = 1;
    }

    ngx_http_dav_ext_flush(r, ll);

    return NGX_OK;
}


static void
ngx_http_dav_ext_send_error(ngx_http_request_t *r)
{
    r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    r->header_only = 1;
    r->headers_out.content_length_n = 0;
    ngx_http_finalize_request(r, ngx_http_send_header(r));
}


static ngx_int_t
ngx_http_dav_ext_parse_header(ngx_http_request_t *r)
{
    ngx_http_dav_ext_ctx_t             *ctx;
    ngx_str_t                          *s;

    ctx = ngx_http_get_module_ctx(r, ngx_http_dav_ext_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dav_ext_ctx_t));
        ngx_http_set_ctx(r, ctx, ngx_http_dav_ext_module);
    }

    ctx->depth = -1; /* infinity */
    if (r->headers_in.depth) {
        s = &r->headers_in.depth->value;
        if (s->len != sizeof("infinity") - 1
            || ngx_strncasecmp(s->data, (u_char *)"infinity", s->len))
        {
            ctx->depth = ngx_atoi(s->data, s->len);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_dav_ext_parse_body(ngx_http_request_t *r)
{
    ngx_chain_t                        *c;
    ngx_buf_t                          *b;
    XML_Parser                          parser;
    ngx_uint_t                          rc;
    ngx_http_dav_ext_ctx_t             *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_dav_ext_module);
    c = r->request_body->bufs;
    rc = NGX_OK;

    parser = XML_ParserCreate(NULL);
    XML_SetUserData(parser, r);
    XML_SetElementHandler(parser, ngx_http_dav_ext_start_xml_elt,
                                  ngx_http_dav_ext_end_xml_elt);
    XML_SetCharacterDataHandler(parser, ngx_http_dav_ext_xml_data);

    while (c != NULL && c->buf != NULL && !c->buf->last_buf) {
        b = c ->buf;
        if (!XML_Parse(parser, (const char*)b->pos, b->last - b->pos, 
                    b->last_buf)) 
        {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                    "dav_ext XML error");
            rc = NGX_ERROR;
            break;
        }
        c = c->next;
    }
    XML_ParserFree(parser);

    return rc;
}


static void
ngx_http_dav_ext_propfind_handler(ngx_http_request_t *r)
{
    if (ngx_http_dav_ext_parse_header(r) != NGX_OK
            || ngx_http_dav_ext_parse_body(r) != NGX_OK) {
        ngx_http_dav_ext_send_error(r);
        return;
    }

    r->headers_out.status = 207;
    ngx_str_set(&r->headers_out.status_line, "207 Multi-Status");
    ngx_http_send_header(r);
    ngx_http_finalize_request(r, ngx_http_dav_ext_send_propfind(r));
}


static void
ngx_http_dav_ext_fill_token(ngx_http_dav_ext_lock_t *lck)
{
    /*TODO*/
    /*
    h->value.len = sizeof("opaquelocktocken:") - 1 + r->uri.len;
    h->value.data = ngx_palloc(r->pool, r->value.len);
    p = ngx_cpymem(h->value.data, "opaquelocktocken:", 
            sizeof("opaquelocktocken:") - 1);
    ngx_memcpy(p, r->uri.data, r->uri.len);
    */
    lck->token = lck->path;
}

/*
static void
ngx_htp_dav_ext_lock_expired(ngx_event_t *e)
{
    ngx_http_dav_ext_lock_t       **llck, *lck;

    lck = e->data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, e->log, 0,
            "dav_ext: timer expired: %i sec");

    llck = ngx_http_dav_ext_get_lock(dlcf->cache, &lck->uri);
}
*/

static void
ngx_http_dav_ext_lock_handler(ngx_http_request_t *r)
{
    ngx_table_elt_t                *h;
    ngx_http_dav_ext_lock_t        *lck;
    ngx_http_dav_ext_ctx_t         *ctx;
    ngx_http_dav_ext_loc_conf_t    *dlcf;

    /* TODO: handle lock refresh */
    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_ext_module);

    if (ngx_http_dav_ext_parse_header(r) != NGX_OK
        || ngx_http_dav_ext_parse_body(r) != NGX_OK) 
    {
        ngx_http_dav_ext_send_error(r);
        return;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_dav_ext_module);

    if (r->headers_in.user.len == 0) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                "dav_ext: unauthorized lock");
        ngx_http_dav_ext_send_error(r);
        return;
    }

    lck = ngx_http_dav_ext_get_lock(dlcf->cache, &r->uri);
    if (lck) {
        if (r->headers_in.user.len != lck->user.len
            || ngx_memcmp(r->headers_in.user.data,
                          lck->user.data, lck->user.len))
        {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                "dav_ext: already locked by another user");
            ngx_http_dav_ext_send_error(r);
            return;
        }

        goto refresh;
    }

    lck = ngx_pcalloc(r->pool, sizeof(ngx_http_dav_ext_lock_t));
    if (lck == NULL) {
        ngx_http_dav_ext_send_error(r);
        return;
    }

    lck->depth = ctx->depth;
    lck->path = r->uri;
    lck->user = ctx->lock_owner;
/*    lck->owner = r->headers_in.user;*/

    ngx_http_dav_ext_fill_token(lck);
    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        ngx_http_dav_ext_send_error(r);
        return;
    }
    ngx_str_set(&h->key, "Lock-Token");
    h->value.len = lck->token.len;
    h->value.data = ngx_palloc(r->pool, lck->token.len);
    ngx_memcpy(h->value.data, lck->token.data, lck->token.len);
    h->hash = 1;
/*
    lck->expire.data = lck;
    lck->expire.handler = ngx_htp_dav_ext_lock_expired;
    lck->expire.log = dlcf->log;
*/

    if (ngx_http_dav_ext_add_lock(dlcf->cache, lck) != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "dav_ext: failed to add lock");
        ngx_http_dav_ext_send_error(r);
        return;
    }

refresh:
    lck->expire = ngx_cached_time->sec + NGX_HTTP_DAV_EXT_TIMEOUT;
    /*ngx_add_timer(&(*llck)->expire, (*llck)->timeout * 1000);*/

    r->headers_out.status = NGX_HTTP_OK;
    ngx_http_send_header(r);
    ngx_http_finalize_request(r, ngx_http_dav_ext_send_lock(r, lck));
}


static ngx_int_t
ngx_http_dav_ext_unlock_handler(ngx_http_request_t *r)
{
	static ngx_str_t                lock_token_field
        = ngx_string("Lock-Tocken");

	ngx_http_variable_value_t       lock_token;
    ngx_http_dav_ext_lock_t        *lck;
    ngx_http_dav_ext_loc_conf_t    *dlcf;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_ext_module);

    if (r->headers_in.user.len == 0) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                "dav_ext: unauthorized unlock");
        return NGX_ERROR;
    }

	if (ngx_http_variable_unknown_header(&lock_token, &lock_token_field,
					&r->headers_in.headers.part, 0) != NGX_OK
		|| !lock_token.valid)
    {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                "dav_ext: no lock-token in unlock");
        return NGX_ERROR;
    }

    lck = ngx_http_dav_ext_get_lock(dlcf->cache, &r->uri);
    if (lck == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "dav_ext: resource not locked");
        return NGX_ERROR;
    }

    if (lck->user.len != r->headers_in.user.len
       || ngx_memcmp(lck->user.data, r->headers_in.user.data,
                     lck->user.len))
    {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                "dav_ext: unlock user mismatch: '%V' '%V'",
                &lck->user, &r->headers_in.user);
        return NGX_ERROR;
    }

    if (lck->token.len != lock_token.len
            || ngx_memcmp(lck->token.data, lock_token.data,
                lck->token.len))
    {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                "dav_ext: unlock token mismatch: '%V' '%*s'",
                &lck->token, lock_token.len, lock_token.data);
        return NGX_ERROR;
    }

    /*
    if (lck->expire.timer_set) {
        ngx_del_timer(&lck->expire);
    }*/

    ngx_http_dav_ext_delete_lock(dlcf->cache, lck);

    r->headers_out.status = NGX_HTTP_NO_CONTENT;
    r->header_only = 1;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);

    return NGX_OK;
}


static ngx_int_t
ngx_http_dav_ext_options_handler(ngx_http_request_t *r)
{
    ngx_table_elt_t              *h;

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

    ngx_str_set(&h->key, "Allow");
    ngx_str_set(&h->value, "GET,HEAD,PUT,DELETE,MKCOL,COPY,MOVE,"
            "PROPFIND,OPTIONS,LOCK,UNLOCK");
    h->hash = 1;

    r->headers_out.status = NGX_HTTP_OK;
    r->header_only = 1;
    r->headers_out.content_length_n = 0;

    ngx_http_send_header(r);

    return NGX_OK;
}


static ngx_int_t
ngx_http_dav_ext_handler(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_http_dav_ext_loc_conf_t    *dlcf;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_ext_module);

    if (!(r->method & dlcf->methods)) {
        return NGX_DECLINED;
    }

    switch (r->method) {

        case NGX_HTTP_PROPFIND:

            rc = ngx_http_read_client_request_body(r, 
                    ngx_http_dav_ext_propfind_handler);

            if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
                return rc;
            }

            return NGX_DONE;   

        case NGX_HTTP_LOCK:

            rc = ngx_http_read_client_request_body(r, 
                    ngx_http_dav_ext_lock_handler);

            if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
                return rc;
            }

            return NGX_DONE;

        case NGX_HTTP_UNLOCK:

            return ngx_http_dav_ext_unlock_handler(r);

        case NGX_HTTP_OPTIONS:

            return ngx_http_dav_ext_options_handler(r);
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

    conf->log = &cf->cycle->new_log;

    return conf;
}


static char *
ngx_http_dav_ext_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_dav_ext_loc_conf_t    *prev = parent;
    ngx_http_dav_ext_loc_conf_t    *conf = child;
    ngx_str_t                       name = ngx_string(
                                           NGX_HTTP_DAV_EXT_LOCK_ZONE);

    ngx_conf_merge_bitmask_value(conf->methods, prev->methods,
            (NGX_CONF_BITMASK_SET|NGX_HTTP_DAV_EXT_OFF));

    if (conf->methods & (NGX_HTTP_LOCK|NGX_HTTP_UNLOCK)) {

        conf->cache = ngx_pcalloc(cf->pool, sizeof(ngx_http_dav_ext_cache_t));
        if (conf->cache == NULL) {
            return NGX_CONF_ERROR;
        }

        conf->cache->shm_zone = ngx_shared_memory_add(cf, &name, 
                NGX_HTTP_DAV_EXT_LOCK_SIZE, &ngx_http_dav_ext_module);
        if (conf->cache->shm_zone == NULL) {
            return NGX_CONF_ERROR;
        }

        if (conf->cache->shm_zone->data) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "duplicate zone \"%V\"", name);
            return NGX_CONF_ERROR;
        }

        conf->cache->shm_zone->init = ngx_http_dav_ext_locks_init;
        conf->cache->shm_zone->data = conf->cache;
    }

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
