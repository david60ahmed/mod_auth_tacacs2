/*=============================================================================
 * Copyright (c) 1998-1999 The Apache Group.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Group.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *=============================================================================
 *
 * NAME
 *	mod_auth_tacacs - Tacacs+ authentication module
 *
 * AUTHOR
 *	Roman Volkov <rv@kht.ru>
 *	Ronan-Yann Lorin <ryl@free.fr>
 *
 * VERSION
 *	$Revision: 1.2 $
 *
 * DOCUMENTATION
 * for use as DSO:
 * LoadModule auth_tacacs_module  libexec/mod_auth_tacacs.so
 * AddModule mod_auth_tacacs.c
 *
 * <directory /web/docs/private>
 * # only one tacacs+ host
 * Tacacs_Pri_Host localhost
 * Tacacs_Pri_Key tac_key
 * Tacacs_Pri_Port tac_port
 * or
 * # double tacacs+ server method (first try to primary, if fail - secondary)
 * # tac_port value - optional, default value - 49 (RFC tacacs+ port)
 * Tacacs_Pri_Host  tac_host_1
 * Tacacs_Pri_Key tac_key_1
 * Tacacs_Pri_Port tac_port_1
 * Tacacs_Sec_Host  tac_host_2
 * Tacacs_Sec_Key tac_key_2
 * Tacacs_Sec_Port tac_port_2
 *
 * Tacacs_Timeout connect_timeout
 *
 * # enable/disable tacacs+ authorization
 * Tacacs_Authorization  on/off
 * # enable/disable tacacs+ accounting
 * Tacacs_Accounting     on/off
 *
 * Tacacs_Authoritative   on
 *
 * AuthName             "example tacacs realm"
 * AuthType             Basic
 *
 *                      Normal apache/ncsa tokens for access control
 *
 * <limit GET POST HEAD>
 *   order deny,allow
 *
 *   require valid-user
 *                     'valid-user'; allow in any user which has a valid uid/pa>
 *                     pair in the above pwd_table.
 * or
 *   require user smith jones
 *                    Limit access to users who have a valid uid/passwd pair in>
 *                    above pwd_table AND whose uid is 'smith' or 'jones'. Do n>
 *                    the uid's are separated by 'spaces' for historic (ncsa) r>
 *                    So allowing uids with spaces might cause problems.
 *
 *   </limit>
 * </directory>
 *
 * tac_plus sample config:
 *  user = www-admin {
 *	default service = deny
 *	service=connection {}
 *  }
 *
 * tacppd sample config:
 *  in table t_avpairs:
 *       service  |  protocol |  av-pairs
 *     -----------+-----------+-----------
 *     connection |    http   |
 *
 *
 * HOW DOES IT WORK?
 *	Some (very) short explains...
 *
 * CHANGELOG
 *	$Log: mod_auth_tacacs.c,v $
 *	Revision 1.2  2003/12/05 21:44:26  ryl
 *	Added Roman's changes for Apache 2.0
 *	
 *	Revision 1.1.1.1  2002/02/17 13:15:30  ryl
 *	Initial source import.
 *	
 *
 *
 *=============================================================================
 */
static char const rcsid [] = "$Id: mod_auth_tacacs.c,v 1.2 2003/12/05 21:44:26 ryl Exp $";

#define APACHE2 0

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#if APACHE2
#include "apr_hooks.h"
#include "apr.h"
#include "apr_compat.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "apr_network_io.h"
#include "apr_pools.h"
#include "apr_uri.h"
#include "apr_fnmatch.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"
#else
#include "http_conf_globals.h"
#endif

#include "mod_tac.h"

#define	LENTACACSNAME	32

/*
 * uncomment the following line if you're having problem. The debug messages
 * will be written to the server error log.
 * WARNING: we log sensitive data, do not use on production systems
 */
/*#define MOD_TACACS_DEBUG 1*/
#undef MOD_TACACS_DEBUG

#if APACHE2

/*
 * "Server/Directory" config for the module
 */
typedef struct {
  const char	*dir;
  const char	*tac_pri_host;
  int		tac_pri_port;
  const char	*tac_pri_key;
  const char	*tac_sec_host;
  int		tac_sec_port;
  const char	*tac_sec_key;
  int		tac_timeout;
  int		tac_authoritative;
  int		tac_authorization;
  int		tac_accounting;
  apr_table_t	*cache_pass_table;
} tacacs_conf;

#ifndef MAX_TABLE_LEN
#define MAX_TABLE_LEN 50
#endif

#else
/*
 * "Server/Directory" config for the module
 */
typedef struct tacacs_sconf {
    char*	tac_pri_host;
    int		tac_pri_port;
    char*	tac_pri_key;
    char*	tac_sec_host;
    int		tac_sec_port;
    char*	tac_sec_key;
    int		tac_timeout;
} tacacs_sconf;

/*
 * "Directory" config for the module
 */
typedef struct tacacs_dconf {
    int   tac_authoritative;
    int   tac_authorization;
    int   tac_accounting;
} tacacs_dconf;

#endif

/*
 * Default cookies name.
 */
#define TACACS_COOKIE_NAME	"webid2"

/*
 * Authentication cookie
 *
 * Public part is used for webid2 cookie client has to send to authenticate
 * for each request.
 *
 * Public + Private parts are stored in cache. Checks are:
 *   - <webid2 from client>     == <public part from cache>
 *   - <client remote ip>       == <remote ip from cache>
 *   - <user-agent from client> == <user-agent from cache>
 *
 */
typedef struct tacacs_webid {
  /*
   * Public part: set when really authenticated.
   */
  char			username [LENTACACSNAME];
  time_t		first_time;		/* first auth. use	*/
  /*
   * Private part: set when user is authenticating.
   */
  time_t		last_time;		/* last auth. use	*/
  char			user_agent [64];	/* user-agent		*/
  char			from_agent [16];	/* remote ip		*/
} tacacs_webid;

/*
 * TTL expire type:
 *   - Cookies expire always after specified time
 *   - Cookies expire if not used for specified time
 */
#define	TACACS_TTL_ALWAYS	0
#define	TACACS_TTL_UNUSED	(!TACACS_TTL_ALWAYS)
#define	TACACS_TTL_ALWAYS_STR	"always_after"
#define	TACACS_TTL_UNUSED_STR	"if_not_used"

#if APACHE2

/*
 * Pre-declaration of the module for the cross-references
 */
module AP_MODULE_DECLARE_DATA auth_tacacs_module;

static apr_pool_t *auth_tac_pool = NULL;

/*
 * Create server/directory config.
 */
void *tacacs_create_conf(apr_pool_t *p, char *d) {
  tacacs_conf	*new_conf;
#if MOD_TACACS_DEBUG
  ap_log_error (APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, p,
		 "#%ld: tacacs_create_conf",(long) getpid ());
#endif
  /* We create a new config */
  new_conf = (tacacs_conf *) apr_pcalloc (p, sizeof (tacacs_conf));
  if(new_conf == NULL) return NULL;

  if(auth_tac_pool == NULL) apr_pool_create_ex(&auth_tac_pool, NULL, NULL, NULL);
  if(auth_tac_pool == NULL) return NULL;

  /*
   * Init default values for config directives. We need to "strdup" variables
   * that will be used with "putenv" (unless it core dumps with some other
   * modules).
   */
  if(d != NULL) new_conf->dir = apr_pstrdup(p, d);
  else new_conf->dir = NULL;
  new_conf->tac_pri_host = NULL;   /* no tacacs host by default */
  new_conf->tac_pri_port = 49;
  new_conf->tac_pri_key = apr_pstrdup(p, "");
  new_conf->tac_sec_host = NULL;
  new_conf->tac_sec_port = 49;
  new_conf->tac_sec_key = apr_pstrdup(p, "");
  new_conf->tac_timeout = 3;
  new_conf->tac_authoritative = 1; /* keep the fortress secure by default */
  new_conf->tac_authorization = 0; /* no authorization by default */
  new_conf->tac_accounting = 0;    /* no accounting by default */

  /* make a per directory cache table */
  new_conf->cache_pass_table = apr_table_make(auth_tac_pool, MAX_TABLE_LEN);
  if(new_conf->cache_pass_table == NULL) return NULL;

  /* And return this config */
  return (void *)new_conf;
}

static int                                                                      
tac_auth_init_handler(apr_pool_t *p,apr_pool_t *plog,apr_pool_t *ptemp,server_rec *s) {
#ifdef MOD_TACACS_DEBUG
  ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, p,
    "[mod_auth_tacacs.c] - tac_auth_init_handler - ");
#endif
  ap_add_version_component(p, "mod_auth_tacacs/2");
  return OK;
}

/*
 * Init the module private memory pool, used for the per directory cache tables 
 */
static void *tacacs_create_server_conf(apr_pool_t *p, server_rec *s) {
#ifdef MOD_TACACS_DEBUG
  ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, p,
    "[mod_auth_tacacs.c] - tacacs_create_server_conf -");
#endif
  if(auth_tac_pool == NULL)
    apr_pool_create_ex(&auth_tac_pool, NULL, NULL, NULL);
  return OK;
}

static const command_rec tacacs_cmds[] = {
  AP_INIT_TAKE1("Tacacs_Pri_Host",ap_set_string_slot,
    (void*)APR_OFFSETOF(tacacs_conf,tac_pri_host),OR_AUTHCFG,"Primary TACACS+ server hostname"),
  AP_INIT_TAKE1("Tacacs_Pri_Port",ap_set_int_slot,
    (void*)APR_OFFSETOF(tacacs_conf,tac_pri_port),OR_AUTHCFG,"Primary TACACS+ server tcp port"),
  AP_INIT_TAKE1("Tacacs_Pri_Key",ap_set_string_slot,
    (void*)APR_OFFSETOF(tacacs_conf,tac_pri_key),OR_AUTHCFG,"Primary TACACS+ server key"),
  AP_INIT_TAKE1("Tacacs_Sec_Host",ap_set_string_slot,
    (void*)APR_OFFSETOF(tacacs_conf,tac_sec_host),OR_AUTHCFG,"Secondary TACACS+ server hostname"),
  AP_INIT_TAKE1("Tacacs_Sec_Port",ap_set_int_slot,
    (void*)APR_OFFSETOF(tacacs_conf,tac_sec_port),OR_AUTHCFG,"Secondary TACACS+ server tcp port"),
  AP_INIT_TAKE1("Tacacs_Sec_Key",ap_set_string_slot,
    (void*)APR_OFFSETOF(tacacs_conf,tac_sec_key),OR_AUTHCFG,"Secondary TACACS+ server key"),
  AP_INIT_TAKE1("Tacacs_Timeout",ap_set_int_slot,
    (void*)APR_OFFSETOF(tacacs_conf,tac_timeout),OR_AUTHCFG,"TCP connection timeout sec"),
  AP_INIT_FLAG("Tacacs_Authorization",ap_set_flag_slot,
    (void*)APR_OFFSETOF(tacacs_conf,tac_authorization),OR_AUTHCFG,"Tacacs authorization on/off"),
  AP_INIT_FLAG("Tacacs_Accounting",ap_set_flag_slot,
    (void*)APR_OFFSETOF(tacacs_conf,tac_accounting),OR_AUTHCFG,"Tacacs accounting on/off"),
  AP_INIT_FLAG("Tacacs_Authoritative",ap_set_flag_slot,
    (void*)APR_OFFSETOF(tacacs_conf,tac_authoritative),OR_AUTHCFG,"Set to 'no' to allow access control to be passed along to lower modules if the UserID is not known to this module "),
  { NULL }
};

#else

/*
 * Pre-declaration of the module for the cross-references
 */
module auth_tacacs_module;

/*
 * Create server config.
 */
static void *tacacs_create_sconf (pool *p, server_rec *s) {
  tacacs_sconf	*sconf;

# if MOD_TACACS_DEBUG
  ap_log_error (APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, s,
		 "#%ld: tacacs_create_sconf",
		 (long) getpid ());
# endif

  /*
   * We create a new config
   */
  sconf = (tacacs_sconf *) ap_pcalloc (p, sizeof (tacacs_sconf));

  /*
   * Init default values for config directives. We need to "strdup" variables
   * that will be used with "putenv" (unless it core dumps with some other
   * modules).
   */
    sconf->tac_pri_host = NULL;   /* no tacacs host by default */
    sconf->tac_pri_port = 49;
    sconf->tac_pri_key = ap_pstrdup (p, "");
    sconf->tac_sec_host = NULL;
    sconf->tac_sec_port = 49;
    sconf->tac_sec_key = ap_pstrdup (p, "");
    sconf->tac_timeout = 3;

  /*
   * And return this config
   */
  return (void *) sconf;
}

/*
 * Create directory config.
 */
static void *tacacs_create_dconf (pool *p, char *d) {
    tacacs_dconf *dconf =
	(tacacs_dconf *) ap_pcalloc (p, sizeof(tacacs_dconf));

    dconf->tac_authoritative = 1; /* keep the fortress secure by default */
    dconf->tac_authorization = 0;
    dconf->tac_accounting = 0;
    return dconf;
}

static const char *tacacs_cfg_pri_host (cmd_parms *cmd, void *dummy, char *arg) {
  /*
   * Server config
   */
  tacacs_sconf	*sconf =
    (tacacs_sconf *) ap_get_module_config (cmd->server->module_config,
                                            &auth_tacacs_module);

  /*
   * Store Tacacs+ Primary server hostname.
   */
  sconf->tac_pri_host = ap_pstrdup (cmd->pool, arg);

# if MOD_TACACS_DEBUG
  ap_log_error (APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, cmd->server,
		 "#%ld: tacacs_cfg_pri_host: %s",
		 (long) getpid (), sconf->tac_pri_host);
# endif

  /*
   * It's ok.
   */
  return NULL;
}

static const char *tacacs_cfg_pri_port(cmd_parms *cmd, void *dummy, char *arg) {
  /*
   * Server config
   */
  tacacs_sconf	*sconf =
    (tacacs_sconf *) ap_get_module_config (cmd->server->module_config,
                                            &auth_tacacs_module);

  /*
   * Store Tacacs+ Primary server port.
   */
  sconf->tac_pri_port = atoi(arg);

  /*
   * It's ok.
   */
  return NULL;
}

static const char *tacacs_cfg_pri_key(cmd_parms *cmd, void *dummy, char *arg) {
  /*
   * Server config
   */
  tacacs_sconf	*sconf =
    (tacacs_sconf *) ap_get_module_config (cmd->server->module_config,
                                            &auth_tacacs_module);

  /*
   * Store Tacacs+ Primary server key.
   */
  sconf->tac_pri_key = ap_pstrdup (cmd->pool, arg);

  /*
   * It's ok.
   */
  return NULL;
}

static const char *tacacs_cfg_sec_host (cmd_parms *cmd, void *dummy, char *arg) {
  /*
   * Server config
   */
  tacacs_sconf	*sconf =
    (tacacs_sconf *) ap_get_module_config (cmd->server->module_config,
                                            &auth_tacacs_module);

  /*
   * Store Tacacs+ secondary server hostname.
   */
  sconf->tac_sec_host = ap_pstrdup (cmd->pool, arg);

# if MOD_TACACS_DEBUG
  ap_log_error (APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, cmd->server,
		 __FILE__"#%ld: tacacs_cfg_sec_host: %s",
		 (long) getpid (), sconf->tac_sec_host);
# endif

  /*
   * It's ok.
   */
  return NULL;
}

static const char *tacacs_cfg_sec_port(cmd_parms *cmd, void *dummy, char *arg) {
  /*
   * Server config
   */
  tacacs_sconf	*sconf =
    (tacacs_sconf *) ap_get_module_config (cmd->server->module_config,
                                            &auth_tacacs_module);

  /*
   * Store Tacacs+ secondary server port.
   */
  sconf->tac_sec_port = atoi(arg);

  /*
   * It's ok.
   */
  return NULL;
}

static const char *tacacs_cfg_sec_key(cmd_parms *cmd, void *dummy, char *arg) {
  /*
   * Server config
   */
  tacacs_sconf	*sconf =
    (tacacs_sconf *) ap_get_module_config (cmd->server->module_config,
                                            &auth_tacacs_module);

  /*
   * Store Tacacs+ Secondary server key.
   */
  sconf->tac_sec_key = ap_pstrdup (cmd->pool, arg);

  /*
   * It's ok.
   */
  return NULL;
}

static const char *tacacs_cfg_timeout(cmd_parms *cmd, void *dummy, char *arg) {
  /*
   * Server config
   */
  tacacs_sconf	*sconf =
    (tacacs_sconf *) ap_get_module_config (cmd->server->module_config,
                                            &auth_tacacs_module);

  /*
   * Store Tacacs+ Timeout.
   */
  sconf->tac_timeout = atoi(arg);

  /*
   * It's ok.
   */
  return NULL;
}

static command_rec tacacs_cmds[] = {
{ "Tacacs_Pri_Host", tacacs_cfg_pri_host, NULL, RSRC_CONF, TAKE1,
     "Primary TACACS+ server hostname" },
{ "Tacacs_Pri_Port", tacacs_cfg_pri_port, NULL, RSRC_CONF, TAKE1,
     "Primary TACACS+ server port (default to 49)" },
{ "Tacacs_Pri_Key", tacacs_cfg_pri_key, NULL, RSRC_CONF, TAKE1,
     "Primary TACACS+ server key" },
{ "Tacacs_Sec_Host", tacacs_cfg_sec_host, NULL, RSRC_CONF, TAKE1,
     "Secondary TACACS+ server hostname" },
{ "Tacacs_Sec_Port", tacacs_cfg_sec_port, NULL, RSRC_CONF, TAKE1,
     "Secondary TACACS+ server port (default to 49)" },
{ "Tacacs_Sec_Key", tacacs_cfg_sec_key, NULL, RSRC_CONF, TAKE1,
     "Secondary TACACS+ server key" },
{ "Tacacs_Timeout", tacacs_cfg_timeout, NULL, RSRC_CONF, TAKE1,
     "TCP connection timeout (default to 3)" },
{ "Tacacs_Authorization", ap_set_flag_slot,
  (void*)XtOffsetOf(tacacs_dconf,tac_authorization), OR_AUTHCFG, FLAG,
     "Tacacs authorization on/off" },
{ "Tacacs_Accounting", ap_set_flag_slot,
  (void*)XtOffsetOf(tacacs_dconf,tac_accounting), OR_AUTHCFG, FLAG,
     "Tacacs accounting on/off" },
{ "Auth_Tacacs_Authoritative", ap_set_flag_slot,
  (void*)XtOffsetOf(tacacs_dconf,tac_authoritative), OR_AUTHCFG, FLAG, 
   "Set to 'no' to allow access control to be passed along to lower modules if the UserID is not known to this module " },
{ "Auth_Tacacs_Host", tacacs_cfg_pri_host, NULL, RSRC_CONF, TAKE1,
     "Primary TACACS+ server hostname (obsolete, use Tacacs_Pri_Host instead)" },
{ "Auth_Tacacs_Key", tacacs_cfg_pri_key, NULL, RSRC_CONF, TAKE1,
     "Primary TACACS+ server key (obsolete, use Tacacs_Pri_Key instead)" },
{ NULL }
};

#endif

/* These functions return 0 if client is OK, and proper error status
 * if not... either AUTH_REQUIRED, if we made a check, and it failed, or
 * SERVER_ERROR, if things are so totally confused that we couldn't
 * figure out how to tell if the client is authorized or not.
 *
 * If they return DECLINED, and all other modules also decline, that's
 * treated by the server core as a configuration error, logged and
 * reported as such.
 */

/* Determine user ID, and check if it really is that user, for HTTP
 * basic authentication...
 */
static int tacacs_check_auth(request_rec *r) {
#if APACHE2
  /* Server and directory configs */
  tacacs_conf *conf =
    (tacacs_conf *) ap_get_module_config (r->per_dir_config,&auth_tacacs_module);
  char *user = r->user;
#else
  /*
   * Server and directory configs
   */
  tacacs_sconf	*sconf =
    (tacacs_sconf *) ap_get_module_config (r->server->module_config,
					    &auth_tacacs_module);
  tacacs_dconf	*dconf =
    (tacacs_dconf *) ap_get_module_config (r->per_dir_config,
					    &auth_tacacs_module);
    char *user = r->connection->user;
#endif
    conn_rec *c = r->connection;
    int res;
    int i;
    char username[256];
    int  result = HTTP_UNAUTHORIZED;
    const char *sent_pw;
    char serv_msg[256];
    char data_msg[256];
    struct tac_session *session=NULL;
    char *avpair[256];

  /*
   * AuthType value; if we are here, it must have been set (else, it meens
   * mod_securid is the only mod_auth* compiled and there is no AuthType
   * directive in httpd.conf).
   */
  const char	*auth_type = ap_auth_type (r);

  /*
   * First first of all, check if AuthType is not NULL *and* == "Tacacs+"
   */
  if (auth_type == NULL)
  {
    ap_log_rerror (APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, r,
		   "[%s] no AuthType! Please use one...", __FILE__);
    return DECLINED;			/* should be internal error?	*/
  }
#if 0
  if (strcasecmp (auth_type, "Tacacs+"))
  {
#   if MOD_TACACS_DEBUG
    ap_log_rerror (APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		   "[%s]#%ld: check_auth: not for me (for %s)",
		   __FILE__, (long) getpid (), ap_auth_type (r));
#   endif
    return DECLINED;
  }
#endif

# if MOD_TACACS_DEBUG
  ap_log_rerror (APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		 "[%s]#%ld: check_auth: %s %s",
		 __FILE__, (long) getpid (), r->method, r->uri);
# endif

    if ((res = ap_get_basic_auth_pw (r, &sent_pw))) {
# if MOD_TACACS_DEBUG
        ap_log_rerror (APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		 "[%s]#%ld: check_auth: failed to get password: %d",
		 __FILE__, (long) getpid (), res);
# endif
    	return res;
    }
#if APACHE2
  if((!conf->tac_pri_host || !conf->tac_pri_key) &&
        (!conf->tac_sec_host || !conf->tac_sec_key)) {
#else    
    if( (!sconf->tac_pri_host || !sconf->tac_pri_key) &&
	(!sconf->tac_sec_host || !sconf->tac_sec_key)) {
#endif
# if MOD_TACACS_DEBUG
        ap_log_rerror (APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		 "[%s]#%ld: check_auth: no server configured",
		 __FILE__, (long) getpid ());
# endif
	return DECLINED;
    }

    /* Fill in User-Name */
    bzero(username, sizeof(username));
    strncpy(username, user, sizeof(username)-1);
    /****************************************************************/
    /*********** AUTHENTICATION ***************/
#if APACHE2
  if(conf->tac_pri_host && conf->tac_pri_key)
    session = tac_connect(conf->tac_pri_host,conf->tac_timeout,conf->tac_pri_key,conf->tac_pri_port);
  if(!session) {
    if(conf->tac_sec_host && conf->tac_sec_key)
      session = tac_connect(conf->tac_sec_host,conf->tac_timeout,conf->tac_sec_key,conf->tac_sec_port);
  }
#else
    if(sconf->tac_pri_host && sconf->tac_pri_key)
	session = tac_connect(sconf->tac_pri_host, sconf->tac_timeout, sconf->tac_pri_key, sconf->tac_pri_port);
    if(!session) {
	if(sconf->tac_sec_host && sconf->tac_sec_key)
	    session = tac_connect(sconf->tac_sec_host, sconf->tac_timeout, sconf->tac_sec_key, sconf->tac_sec_port);
    }
#endif
    if (session) {
	tac_authen_send_start(session,"Apache",username,TACACS_ASCII_LOGIN,"");
	i = tac_authen_get_reply(session,serv_msg,data_msg);
	if (i != -1) {
	    tac_authen_send_cont(session,sent_pw,"");
	    i = tac_authen_get_reply(session,serv_msg,data_msg);
	    if (i == 1) result = OK;
	}
	tac_close(session);
	if (result == OK) {
	    ap_log_rerror (APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
				 "[%s]#%ld: check_auth: %s %s SUCESS",
				 __FILE__, (long) getpid (), r->method, r->uri);
	} else {
	    tac_error("mod_auth_tacacs: authentication failed for: %s",
		    username);
	    ap_note_basic_auth_failure(r);
	    return result;
	}
    } else {
    tac_error("mod_auth_tacacs: authen: can't connect to TACACS server %s:%d/%s:%d",
#if APACHE2
	      conf->tac_pri_host ? conf->tac_pri_host : "<null>", conf->tac_pri_port, conf->tac_sec_host ? conf->tac_sec_host : "<null>", conf->tac_sec_port);
#else
	      sconf->tac_pri_host ? sconf->tac_pri_host : "<null>", sconf->tac_pri_port, sconf->tac_sec_host ? sconf->tac_sec_host : "<null>", sconf->tac_sec_port);
#endif
	return HTTP_UNAUTHORIZED;
    }
    /************* AUTHORIZATION *****************/
#if APACHE2
  if(conf->tac_authorization) {
    if(conf->tac_pri_host && conf->tac_pri_key)
	session = tac_connect(conf->tac_pri_host,conf->tac_timeout,conf->tac_pri_key,conf->tac_pri_port);
    if(!session) {
      if(conf->tac_sec_host && conf->tac_sec_key)
        session = tac_connect(conf->tac_sec_host,conf->tac_timeout,conf->tac_sec_key,conf->tac_sec_port);
    }
#else
    if(dconf->tac_authorization) {
	if(sconf->tac_pri_host && sconf->tac_pri_key)
	    session = tac_connect(sconf->tac_pri_host, sconf->tac_timeout, sconf->tac_pri_key, sconf->tac_pri_port);
	if(!session) {
	    if(sconf->tac_sec_host && sconf->tac_sec_key)
		session = tac_connect(sconf->tac_sec_host, sconf->tac_timeout, sconf->tac_sec_key, sconf->tac_sec_port);
	}
#endif
	if(session) {
	    result = HTTP_UNAUTHORIZED;
	    /* tacppd-style authorization (i think, more understable) */
	    avpair[0]=strdup("service=connection");
	    avpair[1]=strdup("protocol=http");
	    avpair[2]=NULL;
	    tac_author_send_request(session,TAC_PLUS_AUTHEN_METH_TACACSPLUS,
		TAC_PLUS_PRIV_LVL_MIN,TAC_PLUS_AUTHEN_TYPE_ASCII,
		TAC_PLUS_AUTHEN_SVC_LOGIN,username,"Apache",avpair);
	    tac_free_avpairs(avpair);
	    i = tac_author_get_response(session,serv_msg,data_msg,avpair);
	    tac_free_avpairs(avpair);
	    if(i == TAC_PLUS_AUTHOR_STATUS_PASS_ADD) result = OK;
	    if(result != OK) return result;
	} else {
    	    tac_error(
	    "mod_auth_tacacs: author: can't connect to TACACS server %s/%s",
#if APACHE2
	      conf->tac_pri_host ? conf->tac_pri_host : "<null>", conf->tac_sec_host ? conf->tac_sec_host : "<null>");
#else
	      sconf->tac_pri_host ? sconf->tac_pri_host : "<null>", sconf->tac_sec_host ? sconf->tac_sec_host : "<null>");
#endif
	    return HTTP_UNAUTHORIZED;
	}
    }
    /************* ACCOUNTING ****************/
#if APACHE2
  if(conf->tac_accounting) {
    if(conf->tac_pri_host && conf->tac_pri_key)
      session = tac_connect(conf->tac_pri_host,conf->tac_timeout,conf->tac_pri_key,conf->tac_pri_port);
    if(!session) {
      if(conf->tac_sec_host && conf->tac_sec_key)
	session = tac_connect(conf->tac_sec_host,conf->tac_timeout,conf->tac_sec_key,conf->tac_sec_port);
    }
#else
    if(dconf->tac_accounting) {
	if(sconf->tac_pri_host && sconf->tac_pri_key)
	    session = tac_connect(sconf->tac_pri_host, sconf->tac_timeout, sconf->tac_pri_key, sconf->tac_pri_port);
	if(!session) {
	    if(sconf->tac_sec_host && sconf->tac_sec_key)
		session = tac_connect(sconf->tac_sec_host, sconf->tac_timeout, sconf->tac_sec_key, sconf->tac_sec_port);
	}
#endif
	if(session) {
	    avpair[0] = strdup("service=connection");
	    avpair[1] = strdup("protocol=http");
	    avpair[2] = NULL;
	    tac_account_send_request(session,TAC_PLUS_ACCT_FLAG_START,
		TAC_PLUS_AUTHEN_METH_TACACSPLUS,TAC_PLUS_PRIV_LVL_MIN,
		TAC_PLUS_AUTHEN_TYPE_ASCII,TAC_PLUS_AUTHEN_SVC_LOGIN,
		username,"Apache",avpair);		
	    tac_free_avpairs(avpair);
	    i = tac_account_get_reply(session,serv_msg,data_msg);
	    tac_close(session);
	} else {
    	    tac_error(
	      "mod_auth_tacacs: account: can't connect to TACACS server %s/%s",
#if APACHE2
	conf->tac_pri_host ? conf->tac_pri_host : "<null>",conf->tac_sec_host ? conf->tac_sec_host : "<null>");
#else
	      sconf->tac_pri_host ? sconf->tac_pri_host : "<null>", sconf->tac_sec_host ? sconf->tac_sec_host : "<null>");
#endif
	}
    }
    /******************************************************************/
    return result;
}
    
/* Checking ID */
    
static int tacacs_check_access (request_rec *r) {
#if APACHE2
    tacacs_conf *sec = (tacacs_conf*)ap_get_module_config(r->per_dir_config,&auth_tacacs_module);
    char *user = r->user;
    const apr_array_header_t *reqs_arr = (apr_array_header_t*)ap_requires (r);
#else
    tacacs_dconf *sec =
     (tacacs_dconf *)ap_get_module_config (
        	    r->per_dir_config, &auth_tacacs_module);
    char *user = r->connection->user;
        const array_header *reqs_arr = ap_requires (r); 
#endif
    int m = r->method_number;
    int method_restricted = 0;
    register int x;
    const char *t, *w;
    require_line *reqs;

    if(!reqs_arr) return OK;
    reqs = (require_line *)reqs_arr->elts;

    for(x=0; x < reqs_arr->nelts; x++) {
	if (! (reqs[x].method_mask & (1 << m))) continue;
	method_restricted = 1;
	t = reqs[x].requirement;
	w = ap_getword(r->pool, &t, ' ');
	if(!strcmp(w,"valid-user"))
	    return OK;
	if(!strcmp(w,"user")) {
            while(t[0]) {
                w = ap_getword_conf (r->pool, &t);
                if(!strcmp(user,w))
                    return OK;
            }
        }
	else if(!strcmp(w,"group"))
	        return DECLINED;	/* DBM group?  Something else? */
    }
    if (!method_restricted)
      return OK;
    if (!sec->tac_authoritative)
      return DECLINED;
    ap_note_basic_auth_failure (r);
    return HTTP_UNAUTHORIZED;
}

#if APACHE2

static void register_hooks(apr_pool_t * p) {
  ap_hook_post_config(tac_auth_init_handler, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_auth_checker(tacacs_check_access, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_check_user_id(tacacs_check_auth, NULL, NULL, APR_HOOK_MIDDLE);
};

module AP_MODULE_DECLARE_DATA auth_tacacs_module = {
   STANDARD20_MODULE_STUFF,
   tacacs_create_conf,          /* create per-dir    config structures	*/
   NULL,			/* merge  per-dir    config structures	*/
   tacacs_create_server_conf,	/* create per-server config structures	*/
   NULL,			/* merge  per-server config structures	*/
   tacacs_cmds,                 /* table of config file commands	*/
   register_hooks		/* Apache2 register hooks */
};

#else

module MODULE_VAR_EXPORT auth_tacacs_module = {
   STANDARD_MODULE_STUFF,
   NULL,                        /* module initializer			*/
   tacacs_create_dconf,         /* create per-dir    config structures	*/
   NULL,			/* merge  per-dir    config structures	*/
   tacacs_create_sconf,		/* create per-server config structures	*/
   NULL,			/* merge  per-server config structures	*/
   tacacs_cmds,                 /* table of config file commands	*/
   NULL,			/* [#8] MIME-typed-dispatched handlers	*/
   NULL,			/* [#1] URI to filename translation	*/
   tacacs_check_auth,           /* [#4] validate user id from request	*/
   tacacs_check_access,         /* [#5] check if the user is ok _here_	*/
   NULL,			/* [#3] check access by host address	*/
   NULL,			/* [#6] determine MIME type		*/
   NULL,			/* [#7] pre-run fixups			*/
   NULL,			/* [#9] log a transaction		*/
   NULL				/* [#2] header parser			*/
};

#endif
