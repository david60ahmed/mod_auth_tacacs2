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
 *	Roman Volkov <rvolkov@gmail.com>
 *	Ronan-Yann Lorin <ryl@free.fr>
 *
 * VERSION
 *	$Revision: 1.4 $
 *
 * DOCUMENTATION
 * for use as DSO:
 * LoadModule auth_tacacs_module  libexec/mod_auth_tacacs2.so
 *
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
 *	$Log: mod_auth_tacacs2.c,v $
 *	Revision 1.4  2009/07/13 07:23:17  rv1125
 *	*** empty log message ***
 *	
 *	Revision 1.3  2009/07/13 07:21:46  rv1125
 *	*** empty log message ***
 *
 *	Revision 1.2  2009/07/13 07:19:44  rv1125
 *	*** empty log message ***
 *
 *	Revision 1.1  2009/06/17 16:14:06  rv1125
 *	new version for Apache2 and apxs
 *
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
static char const rcsid [] = "$Id: mod_auth_tacacs2.c,v 1.4 2009/07/13 07:23:17 rv1125 Exp $";

#define APACHE2 1

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "apr_hooks.h"
#include "apr.h"
/*#include "apr_compat.h"*/
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "apr_network_io.h"
#include "apr_pools.h"
#include "apr_uri.h"
#include "apr_fnmatch.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"



#include <sys/types.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/time.h>
#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>

#ifdef SYSLOG_IN_SYS
#include <syslog.h>
#else
#include <sys/syslog.h>
#endif
/*#include <utmp.h>*/
#include <unistd.h>
#ifdef SYSV
#include <fcntl.h>
#define index strchr
#else /* ! SYSV */
#include <strings.h>
#endif	/* SYSV */


#define MD5_LEN           16
#define MSCHAP_DIGEST_LEN 49

#ifndef TAC_PLUS_PORT
#define	TAC_PLUS_PORT			49
#endif

#define TAC_PLUS_READ_TIMEOUT		180	/* seconds */
#define TAC_PLUS_WRITE_TIMEOUT		180	/* seconds */
#define TAC_BUF_LEN	257
#define TAC_NAME_LEN	127
#define TAC_IP_ADDR_LEN	16

#define NAS_PORT_MAX_LEN                255

struct tac_session {
    int session_id;                /* host specific unique session id */
    int aborted;                   /* have we received an abort flag? */
    int seq_no;                    /* seq. no. of last packet exchanged */
    time_t last_exch;              /* time of last packet exchange */
    int sock;                      /* socket for this connection */
    char *key;                     /* the key */
    int keyline;                   /* line number key was found on */
    char *peer;                    /* name of connected peer */
    char *cfgfile;                 /* config file name */
    char *acctfile;                /* name of accounting file */
    char port[NAS_PORT_MAX_LEN+1]; /* For error reporting */
    u_char version;                /* version of last packet read */
};

/* types of authentication */
#define TACACS_ENABLE_REQUEST  1    /* Enable Requests */
#define TACACS_ASCII_LOGIN     2    /* Inbound ASCII Login */
#define TACACS_PAP_LOGIN       3    /* Inbound PAP Login */
#define TACACS_CHAP_LOGIN      4    /* Inbound CHAP login */
#define TACACS_ARAP_LOGIN      5    /* Inbound ARAP login */
#define TACACS_PAP_OUT         6    /* Outbound PAP request */
#define TACACS_CHAP_OUT        7    /* Outbound CHAP request */
#define TACACS_ASCII_ARAP_OUT  8    /* Outbound ASCII and ARAP request */
#define TACACS_ASCII_CHPASS    9    /* ASCII change password request */
#define TACACS_PPP_CHPASS      10   /* PPP change password request */
#define TACACS_ARAP_CHPASS     11   /* ARAP change password request */
#define TACACS_MSCHAP_LOGIN    12   /* MS-CHAP inbound login */
#define TACACS_MSCHAP_OUT      13   /* MS-CHAP outbound login */

#define TAC_PLUS_AUTHEN_LOGIN      1
#define TAC_PLUS_AUTHEN_CHPASS     2
#define TAC_PLUS_AUTHEN_SENDPASS   3    /* deprecated */
#define TAC_PLUS_AUTHEN_SENDAUTH   4

/* status of reply packet, that client get from server in authen */
#define TAC_PLUS_AUTHEN_STATUS_PASS     1
#define TAC_PLUS_AUTHEN_STATUS_FAIL     2
#define TAC_PLUS_AUTHEN_STATUS_GETDATA  3
#define TAC_PLUS_AUTHEN_STATUS_GETUSER  4
#define TAC_PLUS_AUTHEN_STATUS_GETPASS  5
#define TAC_PLUS_AUTHEN_STATUS_RESTART  6
#define TAC_PLUS_AUTHEN_STATUS_ERROR    7
#define TAC_PLUS_AUTHEN_STATUS_FOLLOW   0x21

#define TAC_AUTHEN_START_FIXED_FIELDS_SIZE	8
#define TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE	6
#define TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE	5
#define TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE	8
#define TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE	6
#define TAC_ACCT_REQ_FIXED_FIELDS_SIZE		9
#define TAC_ACCT_REPLY_FIXED_FIELDS_SIZE	5

/* methods of authorization */
#define TAC_PLUS_AUTHEN_METH_NOT_SET     0  /*0x00*/
#define TAC_PLUS_AUTHEN_METH_NONE        1  /*0x01*/
#define TAC_PLUS_AUTHEN_METH_KRB5        2  /*0x03*/
#define TAC_PLUS_AUTHEN_METH_LINE        3  /*0x03*/
#define TAC_PLUS_AUTHEN_METH_ENABLE      4  /*0x04*/
#define TAC_PLUS_AUTHEN_METH_LOCAL       5  /*0x05*/
#define TAC_PLUS_AUTHEN_METH_TACACSPLUS  6  /*0x06*/   /* use this ? */
#define TAC_PLUS_AUTHEN_METH_GUEST       8  /*0x08*/
#define TAC_PLUS_AUTHEN_METH_RADIUS      16 /*0x10*/
#define TAC_PLUS_AUTHEN_METH_KRB4        17 /*0x11*/
#define TAC_PLUS_AUTHEN_METH_RCMD        32 /*0x20*/

/* priv_levels */
#define TAC_PLUS_PRIV_LVL_MAX    15 /*0x0f*/
#define TAC_PLUS_PRIV_LVL_ROOT   15 /*0x0f*/
#define TAC_PLUS_PRIV_LVL_USER   1  /*0x01*/
#define TAC_PLUS_PRIV_LVL_MIN    0  /*0x00*/

/* authen types */
#define TAC_PLUS_AUTHEN_TYPE_ASCII     1  /*0x01*/    /*  ascii  */
#define TAC_PLUS_AUTHEN_TYPE_PAP       2  /*0x02*/    /*  pap    */
#define TAC_PLUS_AUTHEN_TYPE_CHAP      3  /*0x03*/    /*  chap   */
#define TAC_PLUS_AUTHEN_TYPE_ARAP      4  /*0x04*/    /*  arap   */
#define TAC_PLUS_AUTHEN_TYPE_MSCHAP    5  /*0x05*/    /*  mschap */

/* authen services */
#define TAC_PLUS_AUTHEN_SVC_NONE       0  /*0x00*/
#define TAC_PLUS_AUTHEN_SVC_LOGIN      1  /*0x01*/
#define TAC_PLUS_AUTHEN_SVC_ENABLE     2  /*0x02*/
#define TAC_PLUS_AUTHEN_SVC_PPP        3  /*0x03*/
#define TAC_PLUS_AUTHEN_SVC_ARAP       4  /*0x04*/
#define TAC_PLUS_AUTHEN_SVC_PT         5  /*0x05*/
#define TAC_PLUS_AUTHEN_SVC_RCMD       6  /*0x06*/
#define TAC_PLUS_AUTHEN_SVC_X25        7  /*0x07*/
#define TAC_PLUS_AUTHEN_SVC_NASI       8  /*0x08*/
#define TAC_PLUS_AUTHEN_SVC_FWPROXY    9  /*0x09*/

/* authorization status */
#define TAC_PLUS_AUTHOR_STATUS_PASS_ADD  1  /*0x01*/
#define TAC_PLUS_AUTHOR_STATUS_PASS_REPL 2  /*0x02*/
#define TAC_PLUS_AUTHOR_STATUS_FAIL      16 /*0x10*/
#define TAC_PLUS_AUTHOR_STATUS_ERROR     17 /*0x11*/
#define TAC_PLUS_AUTHOR_STATUS_FOLLOW    33 /*0x21*/

/* accounting flag */
#define TAC_PLUS_ACCT_FLAG_MORE     0x1     /* deprecated */
#define TAC_PLUS_ACCT_FLAG_START    0x2
#define TAC_PLUS_ACCT_FLAG_STOP     0x4
#define TAC_PLUS_ACCT_FLAG_WATCHDOG 0x8

/* accounting status */
#define TAC_PLUS_ACCT_STATUS_SUCCESS     1   /*0x01*/
#define TAC_PLUS_ACCT_STATUS_ERROR       2   /*0x02*/
#define TAC_PLUS_ACCT_STATUS_FOLLOW     33   /*0x21*/


/* All tacacs+ packets have the same header format */
struct tac_plus_pak_hdr {
    u_char version;

#define TAC_PLUS_MAJOR_VER_MASK 0xf0
#define TAC_PLUS_MAJOR_VER      0xc0

#define TAC_PLUS_MINOR_VER_0    0x0
#define TAC_PLUS_VER_0  (TAC_PLUS_MAJOR_VER | TAC_PLUS_MINOR_VER_0)

#define TAC_PLUS_MINOR_VER_1    0x01
#define TAC_PLUS_VER_1  (TAC_PLUS_MAJOR_VER | TAC_PLUS_MINOR_VER_1)

    u_char type;

#define TAC_PLUS_AUTHEN			1
#define TAC_PLUS_AUTHOR			2
#define TAC_PLUS_ACCT			3

    u_char seq_no;		/* packet sequence number */
    u_char encryption;		/* packet is encrypted or cleartext */

#define TAC_PLUS_ENCRYPTED 0x0		/* packet is encrypted */
#define TAC_PLUS_CLEAR     0x1		/* packet is not encrypted */

    int session_id;		/* session identifier FIXME: Is this needed? */
    int datalength;		/* length of encrypted data following this
				 * header */
    /* datalength bytes of encrypted data */
};

#define HASH_TAB_SIZE 157        /* user and group hash table sizes */

#define TAC_PLUS_HDR_SIZE 12

typedef struct tac_plus_pak_hdr HDR;


struct authen_start {
    unsigned char action;
    unsigned char priv_lvl;
    unsigned char authen_type;
    unsigned char service;
    unsigned char user_len;
    unsigned char port_len;
    unsigned char rem_addr_len;
    unsigned char data_len;
};
struct authen_reply {
    unsigned char status;
    unsigned char flags;
    unsigned short msg_len;
    unsigned short data_len;
};

struct authen_cont {
    unsigned short user_msg_len;
    unsigned short user_data_len;
    unsigned char flags;
};

/* An authorization request packet */
struct author {
    unsigned char authen_method;
    unsigned char priv_lvl;
    unsigned char authen_type;
    unsigned char service;

    unsigned char user_len;
    unsigned char port_len;
    unsigned char rem_addr_len;
    unsigned char arg_cnt;             /* the number of args */
};

/* An authorization reply packet */
struct author_reply {
    unsigned char status;
    unsigned char arg_cnt;
    unsigned short msg_len;
    unsigned short data_len;
};

struct acct {
    unsigned char flags;
    unsigned char authen_method;
    unsigned char priv_lvl;
    unsigned char authen_type;
    unsigned char authen_service;
    unsigned char user_len;
    unsigned char port_len;
    unsigned char rem_addr_len;
    unsigned char arg_cnt; /* the number of cmd args */
};

struct acct_reply {
    unsigned short msg_len;
    unsigned short data_len;
    unsigned char status;      /* status */
};

#define TAC_REM_ADDR_LEN	50

extern int tac_error(const char *format, ...);
extern struct tac_session* tac_connect(const char *peer, const int timeout, const char *key, const int port);
extern char *tac_getipfromname(const char *name);
extern int write_packet(struct tac_session *tac_session,unsigned char *pak);
extern unsigned char *read_packet(struct tac_session *tac_session);
extern void tac_close(struct tac_session* tac_session);
extern int tac_authen_get_reply(struct tac_session* session, char* server, char* datas);
extern char* tac_print_authen_status(int status);
extern int tac_authen_send_start(struct tac_session* session, const char* port,
		const char* username, int type, const char* data);
extern int tac_authen_send_cont(struct tac_session* session, const char* user_msg, const char* data);
extern int tac_author_send_request(struct tac_session *session,const int method,const int priv_lvl,
		const int authen_type,const int authen_service,const char *user,const char *port,char **avpair);
extern int tac_author_get_response(struct tac_session *session, char *server_msg,char *data,char **avpair);
extern void tac_free_avpairs(char **avp);
extern char* tac_print_author_status(int status);
extern int tac_account_send_request(struct tac_session *session, const int flag, const int method, const int priv_lvl,
		const int authen_type, const int authen_service,const char *user, const char *port, char **avpair);
extern int tac_account_get_reply(struct tac_session *session, char *server_msg, char *data);
extern char* tac_print_account_status(int status);




#define	LENTACACSNAME	32

/*
 * uncomment the following line if you're having problem. The debug messages
 * will be written to the server error log.
 * WARNING: we log sensitive data, do not use on production systems
 */
/*#define MOD_TACACS_DEBUG 1*/
#undef MOD_TACACS_DEBUG


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

  /* Server and directory configs */
  tacacs_conf *conf =
    (tacacs_conf *) ap_get_module_config (r->per_dir_config,&auth_tacacs_module);
  char *user = r->user;

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

  if((!conf->tac_pri_host || !conf->tac_pri_key) &&
        (!conf->tac_sec_host || !conf->tac_sec_key)) {

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

  if(conf->tac_pri_host && conf->tac_pri_key)
    session = tac_connect(conf->tac_pri_host,conf->tac_timeout,conf->tac_pri_key,conf->tac_pri_port);
  if(!session) {
    if(conf->tac_sec_host && conf->tac_sec_key)
      session = tac_connect(conf->tac_sec_host,conf->tac_timeout,conf->tac_sec_key,conf->tac_sec_port);
  }

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
/*	    ap_log_rerror (APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
				 "[%s]#%ld: check_auth: %s %s SUCESS",
				 __FILE__, (long) getpid (), r->method, r->uri); */
	} else {
	    tac_error("mod_auth_tacacs: authentication failed for: %s",
		    username);
	    ap_note_basic_auth_failure(r);
	    return result;
	}
    } else {
    tac_error("mod_auth_tacacs: authen: can't connect to TACACS server %s:%d/%s:%d",

	      conf->tac_pri_host ? conf->tac_pri_host : "<null>", conf->tac_pri_port, conf->tac_sec_host ? conf->tac_sec_host : "<null>", conf->tac_sec_port);

	return HTTP_UNAUTHORIZED;
    }
    /************* AUTHORIZATION *****************/

  if(conf->tac_authorization) {
    if(conf->tac_pri_host && conf->tac_pri_key)
	session = tac_connect(conf->tac_pri_host,conf->tac_timeout,conf->tac_pri_key,conf->tac_pri_port);
    if(!session) {
      if(conf->tac_sec_host && conf->tac_sec_key)
        session = tac_connect(conf->tac_sec_host,conf->tac_timeout,conf->tac_sec_key,conf->tac_sec_port);
    }

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

	      conf->tac_pri_host ? conf->tac_pri_host : "<null>", conf->tac_sec_host ? conf->tac_sec_host : "<null>");

	    return HTTP_UNAUTHORIZED;
	}
    }
    /************* ACCOUNTING ****************/

  if(conf->tac_accounting) {
    if(conf->tac_pri_host && conf->tac_pri_key)
      session = tac_connect(conf->tac_pri_host,conf->tac_timeout,conf->tac_pri_key,conf->tac_pri_port);
    if(!session) {
      if(conf->tac_sec_host && conf->tac_sec_key)
	session = tac_connect(conf->tac_sec_host,conf->tac_timeout,conf->tac_sec_key,conf->tac_sec_port);
    }

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

	conf->tac_pri_host ? conf->tac_pri_host : "<null>",conf->tac_sec_host ? conf->tac_sec_host : "<null>");

	}
    }
    /******************************************************************/
    return result;
}

/* Checking ID */

static int tacacs_check_access (request_rec *r) {

    tacacs_conf *sec = (tacacs_conf*)ap_get_module_config(r->per_dir_config,&auth_tacacs_module);
    char *user = r->user;
    const apr_array_header_t *reqs_arr = (apr_array_header_t*)ap_requires (r);

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


/*
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>


#include "md5.h"
#include "mod_tac.h"
*/

#include <openssl/md5.h>
#include "util_md5.h"

/*
 *  tac_close - Close connection with TACACS+ server
 */
void tac_close(struct tac_session* tac_session) {
    if (tac_session) {
	if (!tac_session->aborted)
	    close(tac_session->sock);
	if (tac_session->peer) free(tac_session->peer);
	if (tac_session->key) free(tac_session->key);
	free(tac_session);
    }
}

static void tac_abort(struct tac_session *tac_session) {
    tac_session->aborted = 1;
//    tac_close(tac_session);
}

/* catchup function - call from signal */
static void tac_catchup(int s) {
    tac_error("Tacacs+ server not responding!");
}

/*
 *	tac_connect - Connect to TACACS+ server.
 *		peer	server name (or IP adress)
 *		timeout	waiting for connection to establish
 *		key	a kind of encryption key
 *		port	TACACS+ server port
 *	return
 *		NULL	FAILURE
 *		session	SUCCESS
 */
struct tac_session*
tac_connect(const char *peer,
	    const int timeout,
	    const char *key,
	    const int port) {
  int f;
  struct sockaddr_in s;
  void (*oldalrm)();
  static struct tac_session* tac_session;

  tac_session = (struct tac_session *)malloc(sizeof(struct tac_session));
  if (tac_session == NULL) {
       tac_error("tac_connect: Can't allocate memory");
       return NULL;
  }
  bzero(tac_session, sizeof(struct tac_session));
  tac_session->peer = strdup(tac_getipfromname(peer) ? tac_getipfromname(peer) : peer);
  tac_session->key = strdup(key);
  tac_session->aborted = 0;

  /* connection */
  if ((f = socket(AF_INET, SOCK_STREAM, 0)) < 0) tac_abort(tac_session);
  s.sin_addr.s_addr = htonl(INADDR_ANY);
#ifndef __SVR4
#ifndef __linux__
  s.sin_len = sizeof(struct sockaddr_in);
#endif
#endif
  s.sin_family = AF_INET;
  s.sin_port = 0;
  if (bind(f, (struct sockaddr *)&s, sizeof(s)) < 0) tac_abort(tac_session);
  if (!inet_aton(tac_session->peer, &s.sin_addr)) tac_abort(tac_session);
#ifndef __SVR4
#ifndef __linux__
  s.sin_len = sizeof(struct sockaddr_in);
#endif
#endif
  s.sin_family = AF_INET;
  s.sin_port = htons(port);
  oldalrm = signal(SIGALRM, tac_catchup);
  alarm(timeout);
  if (connect(f, (struct sockaddr *)&s, sizeof(s)) < 0) tac_abort(tac_session);
  alarm(0);
  tac_session->sock = f;
  /* for session_id set process pid */
  tac_session->session_id = htonl(getpid());
  /* sequence to zero */
  tac_session->seq_no = 0;
  /* and dont see using this */
  tac_session->last_exch = time(NULL);
  signal(SIGALRM, oldalrm);

  if (tac_session->aborted) {
    tac_close(tac_session);
    tac_session = NULL;
  }
  return tac_session;
}


/*
 * create_md5_hash(): create an md5 hash of the "session_id", "the user's
 * key", "the version number", the "sequence number", and an optional
 * 16 bytes of data (a previously calculated hash). If not present, this
 * should be NULL pointer.
 *
 * Write resulting hash into the array pointed to by "hash".
 *
 * The caller must allocate sufficient space for the resulting hash
 * (which is 16 bytes long). The resulting hash can safely be used as
 * input to another call to create_md5_hash, as its contents are copied
 * before the new hash is generated.
 */

#define MD5_CTX apr_md5_ctx_t
#define MD5Init apr_md5_init
#define MD5Update apr_md5_update
#define MD5Final apr_md5_final

static void
create_md5_hash(int session_id,
		char* key,
		u_char version,
		u_char seq_no,
		u_char* prev_hash,
		u_char* hash) {
    u_char *md_stream, *mdp;
    int md_len;
    MD5_CTX mdcontext;

    md_len = sizeof(session_id) + strlen(key) + sizeof(version) +
	sizeof(seq_no);
    if (prev_hash) {
	md_len += MD5_LEN;
    }
    mdp = md_stream = (u_char *) malloc(md_len);
    bcopy(&session_id, mdp, sizeof(session_id));
    mdp += sizeof(session_id);

    bcopy(key, mdp, strlen(key));
    mdp += strlen(key);

    bcopy(&version, mdp, sizeof(version));
    mdp += sizeof(version);

    bcopy(&seq_no, mdp, sizeof(seq_no));
    mdp += sizeof(seq_no);

    if (prev_hash) {
	bcopy(prev_hash, mdp, MD5_LEN);
	mdp += MD5_LEN;
    }
    MD5Init(&mdcontext);
    MD5Update(&mdcontext, md_stream, md_len);
    MD5Final(hash, &mdcontext);
    free(md_stream);
    return;
}

/*
 * Overwrite input data with en/decrypted version by generating an MD5 hash and
 * xor'ing data with it.
 *
 * When more than 16 bytes of hash is needed, the MD5 hash is performed
 * again with the same values as before, but with the previous hash value
 * appended to the MD5 input stream.
 *
 * Return 0 on success, -1 on failure.
 */
static int md5_xor(HDR* hdr, u_char* data, char* key) {
    int i, j;
    u_char hash[MD5_LEN];       /* the md5 hash */
    u_char last_hash[MD5_LEN];  /* the last hash we generated */
    u_char *prev_hashp = (u_char *) NULL;       /* pointer to last created
						 * hash */
    int data_len;
    int session_id;
    u_char version;
    u_char seq_no;

    data_len = ntohl(hdr->datalength);
    session_id = hdr->session_id; /* always in network order for hashing */
    version = hdr->version;
    seq_no = hdr->seq_no;

    if (!key) return 0;
    for (i = 0; i < data_len; i += 16) {
	create_md5_hash(session_id, key, version, seq_no, prev_hashp, hash);

#ifdef DEBUG_MD5
	 tac_error("hash: session_id=%u, key=%s, version=%d, seq_no=%d",
		   session_id, key, version, seq_no);
#endif
	bcopy(hash, last_hash, MD5_LEN);
	prev_hashp = last_hash;

	for (j = 0; j < 16; j++) {

	    if ((i + j) >= data_len) {
		hdr->encryption = (hdr->encryption == TAC_PLUS_CLEAR)
		    ? TAC_PLUS_ENCRYPTED : TAC_PLUS_CLEAR;
		return 0;
	    }
	    data[i + j] ^= hash[j];
	}
    }
    hdr->encryption = (hdr->encryption == TAC_PLUS_CLEAR)
	? TAC_PLUS_ENCRYPTED : TAC_PLUS_CLEAR;
    return 0;
}

/*
 * Reading n bytes from descriptor fd to array ptr with timeout t sec
 * Timeout set for each read
 *
 * Return -1 if error, eof or timeout. Else returns
 * number reads bytes.
 */
static int
sockread(struct tac_session* tac_session,
	    int fd,
	    u_char* ptr,
	    int nbytes,
	    int timeout) {
    int nleft, nread;
    fd_set readfds, exceptfds;
    struct timeval tout;

    if (fd == -1) return -1;
    tout.tv_sec = timeout;
    tout.tv_usec = 0;

    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);
    FD_ZERO(&exceptfds);
    FD_SET(fd, &exceptfds);

    nleft = nbytes;
    while (nleft > 0) {
	int status = select(fd + 1, &readfds, (fd_set *) NULL,
			    &exceptfds, &tout);
	if (status == 0) {
	    tac_error("%s: timeout reading fd %d",tac_session->peer,fd);
	    return(-1);
	}
	if (status < 0) {
	    if (errno == EINTR) continue;
	    tac_error("%s: error in select (fd %d)",
		   tac_session->peer, fd);
	    return (-1);
	}
	if (FD_ISSET(fd, &exceptfds)) {
	    tac_error("%s: exception on fd %d", tac_session->peer, fd);
	    return (-1);
	}
	if (!FD_ISSET(fd, &readfds)) {
	    tac_error("%s: spurious return from select",tac_session->peer);
	    continue;
	}
    again:
	nread = read(fd, ptr, nleft);

	if (nread < 0) {
	    if (errno == EINTR)
		goto again;
	    tac_error("%s %s: error reading fd %d nread=%d",
		   tac_session->peer,tac_session->port, fd, nread);
	    return (-1);        /* error */

	} else if (nread == 0) {
	    tac_error("%s %s: fd %d eof (connection closed)",
		   tac_session->peer, tac_session->port, fd);
	    return (-1);        /* eof */
	}
	nleft -= nread;
	if (nleft)
	    ptr += nread;
    }
    return (nbytes - nleft);
}

/*
 * Write n bytes to descriptor fd from array ptr with timeout t
 * seconds. Note the timeout is applied to each write, not for the
 * overall operation.
 *
 * Return -1 on error, eof or timeout. Otherwise return number of
 * bytes written.
 */
static int
sockwrite(struct tac_session *tac_session,
	    int fd,
	    const u_char* ptr,
	    int bytes,
	    int timeout) {
    int remaining, sent;
    fd_set writefds, exceptfds;
    struct timeval tout;

    if (fd == -1) return -1;

    sent = 0;
    tout.tv_sec = timeout;
    tout.tv_usec = 0;

    FD_ZERO(&writefds);
    FD_SET(fd, &writefds);
    FD_ZERO(&exceptfds);
    FD_SET(fd, &exceptfds);

    remaining = bytes;

    while (remaining > 0) {
	int status = select(fd + 1, (fd_set *) NULL,
			    &writefds, &exceptfds, &tout);
	if(status == 0) {
	    tac_error("%s: timeout writing to fd %d",
		   tac_session->peer, fd);
	    return (-1);
	}
	if(status < 0) {
	    tac_error("%s: error in select fd %d",
		   tac_session->peer, fd);
	    return (-1);
	}
	if(FD_ISSET(fd, &exceptfds)) {
	    tac_error("%s: exception on fd %d", tac_session->peer, fd);
	    return (sent);      /* error */
	}
	if(!FD_ISSET(fd, &writefds)) {
	    tac_error("%s: spurious return from select",
		   tac_session->peer);
	    continue;
	}
	sent = write(fd, ptr, remaining);

	if(sent <= 0) {
	    tac_error("%s: error writing fd %d sent=%d",
		   tac_session->peer, fd, sent);
	    return (sent);      /* error */
	}
	remaining -= sent;
	ptr += sent;
    }
    return (bytes - remaining);
}

/*
 *	read_packet - Read a packet and decrypt it from TACACS+ server
 *	return
 *		pointer to a newly allocated memory buffer containing packet data
 *		NULL	FAILURE
 */
u_char*
read_packet(struct tac_session *tac_session) {
    HDR hdr;
    u_char *pkt, *data;
    int len;

    /* read a packet header */
    len = sockread(tac_session,tac_session->sock,(u_char *) & hdr,
	TAC_PLUS_HDR_SIZE, TAC_PLUS_READ_TIMEOUT);
    if (len != TAC_PLUS_HDR_SIZE) {
	tac_error("Read %d bytes from %s %s, expecting %d",
	       len, tac_session->peer, tac_session->port, TAC_PLUS_HDR_SIZE);
	return(NULL);
    }
    if ((hdr.version & TAC_PLUS_MAJOR_VER_MASK) != TAC_PLUS_MAJOR_VER) {
	tac_error("%s: Illegal major version specified: found %d wanted %d",
	       tac_session->peer,hdr.version,TAC_PLUS_MAJOR_VER);
	return(NULL);
    }
    /* get memory for the packet */
    len = TAC_PLUS_HDR_SIZE + ntohl(hdr.datalength);
    pkt = (u_char *) malloc(len);

    /* initialise the packet */
    bcopy(&hdr, pkt, TAC_PLUS_HDR_SIZE);

    /* the data start here */
    data = pkt + TAC_PLUS_HDR_SIZE;

    /* read the rest of the packet data */
    if (sockread(tac_session,tac_session->sock,data,ntohl(hdr.datalength),
		 TAC_PLUS_READ_TIMEOUT) != ntohl(hdr.datalength)) {
	tac_error("%s: start_session: bad socket read", tac_session->peer);
	return (NULL);
    }
    tac_session->seq_no++;           /* should now equal that of incoming packet */
    tac_session->last_exch = time(NULL);
    if(tac_session->seq_no != hdr.seq_no) {
	tac_error("%s: Illegal session seq # %d != packet seq # %d",
	       tac_session->peer,
	       tac_session->seq_no, hdr.seq_no);
	return (NULL);
    }
    /* decrypt the data portion */
    if (tac_session->key && md5_xor((HDR *)pkt,data,tac_session->key)) {
	tac_error("%s: start_session error decrypting data",
	       tac_session->peer);
	return (NULL);
    }
    tac_session->version = hdr.version;
    return (pkt);
}

/*
 * write_packet - Send a data packet to TACACS+ server
 *	pak	pointer to packet data to send
 * return
 *	1       SUCCESS
 *	0       FAILURE
 */
int
write_packet(struct tac_session *tac_session, unsigned char *pak) {
    HDR *hdr = (HDR *) pak;
    unsigned char *data;
    int len;

    len = TAC_PLUS_HDR_SIZE + ntohl(hdr->datalength);
    /* the data start here */
    data = pak + TAC_PLUS_HDR_SIZE;
    /* encrypt the data portion */
    if (tac_session->key && md5_xor((HDR *)pak,data,tac_session->key)) {
	tac_error("%s: write_packet: error encrypting data",tac_session->peer);
	return 0;
    }
    if (sockwrite(tac_session,tac_session->sock,pak,len,TAC_PLUS_WRITE_TIMEOUT) != len) {
	return 0;
    }
    tac_session->last_exch = time(NULL);
    return 1;
}

/********************************************************/



/*
 * output error message to syslog
 */
int
tac_error(const char *format, ...) {
	va_list	ap;
	int	result;
	char	errmsg[256];

	va_start(ap, format);
	result = vsnprintf(errmsg, sizeof(errmsg), format, ap);
	syslog (LOG_DAEMON, "mod_auth_tacacs: %s", errmsg);
	va_end(ap);
	return result;
}

/*
 *  tac_getipfromname - get ip addr from name
 *		NULL - FAILURE
 */
char*
tac_getipfromname(const char *name) {
   struct    in_addr  nas_addr;
   struct    hostent *host;
   static    char hostaddr[40];

   host = gethostbyname(name);
   if (host == NULL) {
	tac_error("gethostbyname(%s) failure",name);
	return NULL;
   }
   bcopy(host->h_addr, (char *)&nas_addr, host->h_length);
   strcpy(hostaddr,(char*)inet_ntoa(nas_addr));
   return (hostaddr);
}

/*
 *  translate tacacs server authenticaton reply status
 *  to string (this is for debug purposes)
 */
char*
tac_print_authen_status(int status) {
   switch(status) {
   case 1:
      return("TAC_PLUS_AUTHEN_STATUS_PASS");
      break;
   case 2:
      return("TAC_PLUS_AUTHEN_STATUS_FAIL");
      break;
   case 3:
      return("TAC_PLUS_AUTHEN_STATUS_GETDATA");
      break;
   case 4:
      return("TAC_PLUS_AUTHEN_STATUS_GETUSER");
      break;
   case 5:
      return("TAC_PLUS_AUTHEN_STATUS_GETPASS");
      break;
   case 6:
      return("TAC_PLUS_AUTHEN_STATUS_RESTART");
      break;
   case 7:
      return("TAC_PLUS_AUTHEN_STATUS_ERROR");
      break;
   case 0x21:
      return("TAC_PLUS_AUTHEN_STATUS_FOLLOW");
      break;
   default:
      return("Unknown status");
      break;
  }
  return(NULL);
}

/* free avpairs array */
void
tac_free_avpairs(char **avp) {
   int i=0;
   while (avp[i]!=NULL) free(avp[i++]);
}

/*
 * translate authorization status to string
 * (for debug only)
 */
char*
tac_print_author_status(int status) {
      switch(status) {
       case TAC_PLUS_AUTHOR_STATUS_PASS_ADD:
	  return("TAC_PLUS_AUTHOR_STATUS_PASS_ADD");
	  break;
       case TAC_PLUS_AUTHOR_STATUS_PASS_REPL:
	  return("TAC_PLUS_AUTHOR_STATUS_PASS_REPL");
	  break;
       case TAC_PLUS_AUTHOR_STATUS_FAIL:
	  return("TAC_PLUS_AUTHOR_STATUS_FAIL");
	  break;
       case TAC_PLUS_AUTHOR_STATUS_ERROR:
	  return("TAC_PLUS_AUTHOR_STATUS_ERROR");
	  break;
       case TAC_PLUS_AUTHOR_STATUS_FOLLOW:
	  return("TAC_PLUS_AUTHOR_STATUS_FOLLOW");
	  break;
       default:
	  return("Unknown");
	  break;
      }
      return(NULL);
}

/* translate accounting status to string (debug only) */
char*
tac_print_account_status(int status) {
	switch (status) {
	  case TAC_PLUS_ACCT_STATUS_SUCCESS:
		return("TAC_PLUS_ACCT_STATUS_SUCCESS");
		break;
	  case TAC_PLUS_ACCT_STATUS_ERROR:
		return("TAC_PLUS_ACCT_STATUS_ERROR");
		break;
	  case TAC_PLUS_ACCT_STATUS_FOLLOW:
		return("TAC_PLUS_ACCT_STATUS_FOLLOW");
		break;
	  default:
		return("UNKNOWN");
		break;
	}
	return(NULL);
}








/*
 * authorization
 */


/*
 *    send request (client finction)
 */
int
tac_author_send_request(struct tac_session *session,const int method,
		 const int priv_lvl,const int authen_type,
		 const int authen_service,const char *user,
		 const char *port,char **avpair) {
   int i;
   char name[TAC_NAME_LEN];
   char rem_addr[TAC_REM_ADDR_LEN];
   int arglens=0;
   char buf[TAC_BUF_LEN];
   HDR *hdr = (HDR *)buf;		/* header */
   /* datas */
   struct author *auth=(struct author *)
	    (buf+TAC_PLUS_HDR_SIZE);
   char *lens=(char *)(buf+TAC_PLUS_HDR_SIZE+
		       TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE);

   hdr->version = TAC_PLUS_VER_0;	/* set version to 0 */
   hdr->type = TAC_PLUS_AUTHOR;      /* set packet type to authorization */
   hdr->seq_no = ++session->seq_no;
   hdr->encryption = TAC_PLUS_CLEAR; /*TAC_PLUS_ENCRYPTED;*/
   hdr->session_id = session->session_id;

   /* this is addr */
   gethostname(name,sizeof(name));
   strncpy(rem_addr,tac_getipfromname(name),sizeof(rem_addr));

   /* count length */
   for (i=0; avpair[i]!=NULL ; i++) {
       if (strlen(avpair[i])>255)    /* if lenght of AVP>255 set it to 255 */
	    avpair[i][255]=0;
       arglens += strlen(avpair[i]);
   }

   hdr->datalength = htonl(TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE +
	 i + strlen(user) + strlen(port) +
	 strlen(rem_addr) + arglens);

   auth->authen_method = (unsigned char) method;
   auth->priv_lvl = (unsigned char) priv_lvl;
   auth->authen_type = (unsigned char) authen_type;
   auth->service = (unsigned char) authen_service;
   auth->user_len = (unsigned char) strlen(user);
   auth->port_len = (unsigned char) strlen(port);
   auth->rem_addr_len = (unsigned char) strlen(rem_addr);
   auth->arg_cnt = (unsigned char) i;

   for (i=0; avpair[i]!=NULL ; i++) {
       *lens = (unsigned char) strlen(avpair[i]);
       lens+=1;
   }
   /* now filling some data */
   if (strlen(user) > 0) {
       strcpy(lens,user);
       lens += strlen(user);
   }
   if (strlen(port) > 0) {
       strcpy(lens,port);
       lens += strlen(port);
   }
   if (strlen(rem_addr) > 0) {
       strcpy(lens,rem_addr);
       lens += strlen(rem_addr);
   }
   for (i=0; avpair[i]!=NULL ; i++) {
       strcpy(lens,avpair[i]);
       lens += (u_char)strlen(avpair[i]);
   }
   /* now send */
   if (write_packet(session,buf)) return 1;
   return 0;
}


/* RESPONSEs processing *
status =
TAC_PLUS_AUTHOR_STATUS_PASS_ADD  := 0x01
TAC_PLUS_AUTHOR_STATUS_PASS_REPL := 0x02
TAC_PLUS_AUTHOR_STATUS_FAIL      := 0x10
TAC_PLUS_AUTHOR_STATUS_ERROR     := 0x11
TAC_PLUS_AUTHOR_STATUS_FOLLOW    := 0x21
*/

/*
 *     get RESPONSE (client function)  return status
 */
int
tac_author_get_response(struct tac_session *session,
			    char *server_msg,char *data,char **avpair)
{
   int status;
   char ss[255];
   char *buf = read_packet(session);
   struct author_reply *auth=(struct author_reply *)
	    (buf+TAC_PLUS_HDR_SIZE);
   HDR *hdr = (HDR *)buf;
   char *lens=(char *)(buf+TAC_PLUS_HDR_SIZE+
		     TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE);
   int l[255];    /* I think, that not more 255 avpairs can be processed */
   int arglens = 0;
   int i;

   if (buf==NULL) return 0;
   /* Do some checks */
   if (session == NULL) return -1;
   if (hdr->type != TAC_PLUS_AUTHOR) {
      tac_error("This is not AUTHOR request\n");
      return 0;
   }
   if (hdr->seq_no != 2) {
       tac_error("Error in sequence in AUTHOR/RESPONSE packet\n");
       return 0;
   }
   session->session_id = hdr->session_id;

   status = auth->status;
   avpair[0]=NULL;
   if (status==TAC_PLUS_AUTHOR_STATUS_ERROR) return(status);
   /* count length */
   for (i=0; i < auth->arg_cnt ; i++) {
       arglens += (int)(*(lens+i));
       l[i]=(int)(*(lens+i));
   }
   if (hdr->datalength != htonl(TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE +
      auth->arg_cnt + auth->msg_len + auth->data_len + arglens))
   {
       tac_error("Error in AUTHOR/RESPONSE packet, check keys\n");
       return (status);
   }
   lens=lens+i;
   strncpy(server_msg,lens,auth->msg_len);
   server_msg[auth->msg_len] = 0;
   lens += auth->msg_len;

   strncpy(data,lens,auth->data_len);
   data[auth->data_len] = 0;
   lens += auth->data_len;

   /* write avpairs */
   for (i=0; i < auth->arg_cnt ; i++) {
       strncpy(ss,lens,l[i]);
       lens=lens+l[i];
       ss[l[i]]=0;    /* set 0 */
       avpair[i]=strdup(ss);
       avpair[i+1]=NULL;
   }
   /* now all */
   return (status);
}

/* ------------------------------------------------------- */
/*
 *   AUTHENTICATION
 *
 */
/*
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mod_tac.h"
*/

/*
          types of authentication
TACACS_ENABLE_REQUEST  1    Enable Requests
TACACS_ASCII_LOGIN     2    Inbound ASCII Login
TACACS_PAP_LOGIN       3    Inbound PAP Login
TACACS_CHAP_LOGIN      4    Inbound CHAP login
TACACS_ARAP_LOGIN      5    Inbound ARAP login
TACACS_PAP_OUT         6    Outbound PAP request
TACACS_CHAP_OUT        7    Outbound CHAP request
TACACS_ASCII_ARAP_OUT  8    Outbound ASCII and ARAP request
TACACS_ASCII_CHPASS    9    ASCII change password request
TACACS_PPP_CHPASS      10   PPP change password request
TACACS_ARAP_CHPASS     11   ARAP change password request
TACACS_MSCHAP_LOGIN    12   MS-CHAP inbound login
TACACS_MSCHAP_OUT      13   MS-CHAP outbound login

tac_authen_send_start - send start authentication packet
	(we are as client initiate connection)
	port		tty10 or Async10
	username
	type
	data		external data to tacacs+ server
return
	1       SUCCESS
	0       FAILURE
*/
int tac_authen_send_start(struct tac_session* session, const char* port,
			const char* username, int type, const char* data) {
  char buf[TAC_BUF_LEN];
  char name[TAC_NAME_LEN];
  char addr[TAC_IP_ADDR_LEN];
  HDR *hdr = (HDR *)buf;
  struct authen_start *ask=(struct authen_start *)(buf+TAC_PLUS_HDR_SIZE);
  /* username */
  char *u = (char *)(buf+TAC_PLUS_HDR_SIZE+TAC_AUTHEN_START_FIXED_FIELDS_SIZE);
  char *p = (char *)(u+strlen(username));	/* port */
  char *a = (char *)(p+strlen(port));		/* peer addr */
  char *d;					/* ptr to data */

  if (session == NULL) return 0;
  bzero(buf, sizeof(buf));			/* clear buf */

  /* this is addr */
  gethostname(name,sizeof(name));
  strncpy(addr,tac_getipfromname(name),sizeof(addr)-1);
  d = (char *)(a + strlen(addr));

  /*** header ***/
  /* version (TAC_PLUS_MAJOR_VER | TAC_PLUS_MINOR_VER_0) */
  if  (type == TACACS_ENABLE_REQUEST ||
       type == TACACS_ASCII_LOGIN )
	   hdr->version = TAC_PLUS_VER_0;
  else
	   hdr->version = TAC_PLUS_VER_1;

  hdr->type = TAC_PLUS_AUTHEN;			/* perform authentication */
  /* set sequence, for first request it will be 1 */
  hdr->seq_no = ++(session->seq_no);
  /* encryption TAC_PLUS_ENCRYPTED || TAC_PLUS_CLEAR */
  hdr->encryption = TAC_PLUS_CLEAR;  /*TAC_PLUS_ENCRYPTED;*/
  hdr->session_id = session->session_id;	/* session ID */

  /* data length */
  if (type == TACACS_CHAP_LOGIN || type == TACACS_MSCHAP_LOGIN)
      hdr->datalength = htonl(TAC_AUTHEN_START_FIXED_FIELDS_SIZE
	   +strlen(username)+strlen(port)+strlen(addr)+1+strlen(data));
  else
  if (type == TACACS_PAP_LOGIN || type == TACACS_ARAP_LOGIN)
      hdr->datalength = htonl(TAC_AUTHEN_START_FIXED_FIELDS_SIZE
	   +strlen(username)+strlen(port)+strlen(addr)+strlen(data));
  else
      hdr->datalength = htonl(TAC_AUTHEN_START_FIXED_FIELDS_SIZE
	   +strlen(username)+strlen(port)+strlen(addr));

  ask->priv_lvl = TAC_PLUS_PRIV_LVL_MIN;	/* privilege */
  switch (type)
  {
    case TACACS_ENABLE_REQUEST:
       ask->action = TAC_PLUS_AUTHEN_LOGIN;
       ask->service = TAC_PLUS_AUTHEN_SVC_ENABLE;
       break;
    case TACACS_ASCII_LOGIN:
       ask->action = TAC_PLUS_AUTHEN_LOGIN;
       ask->authen_type = TAC_PLUS_AUTHEN_TYPE_ASCII;
       ask->service = TAC_PLUS_AUTHEN_SVC_LOGIN;
       break;
    case TACACS_PAP_LOGIN:
       ask->action = TAC_PLUS_AUTHEN_LOGIN;
       ask->authen_type = TAC_PLUS_AUTHEN_TYPE_PAP;
       break;
    case TACACS_PAP_OUT:
       ask->action = TAC_PLUS_AUTHEN_SENDAUTH;
       ask->authen_type = TAC_PLUS_AUTHEN_TYPE_PAP;
       break;
    case TACACS_CHAP_LOGIN:
       ask->action = TAC_PLUS_AUTHEN_LOGIN;
       ask->authen_type = TAC_PLUS_AUTHEN_TYPE_CHAP;
       break;
    case TACACS_CHAP_OUT:
       ask->action = TAC_PLUS_AUTHEN_SENDAUTH;
       ask->authen_type = TAC_PLUS_AUTHEN_TYPE_CHAP;
       break;
    case TACACS_MSCHAP_LOGIN:
       ask->action = TAC_PLUS_AUTHEN_LOGIN;
       ask->authen_type = TAC_PLUS_AUTHEN_TYPE_MSCHAP;
       break;
    case TACACS_MSCHAP_OUT:
       ask->action = TAC_PLUS_AUTHEN_SENDAUTH;
       ask->authen_type = TAC_PLUS_AUTHEN_TYPE_MSCHAP;
       break;
    case TACACS_ARAP_LOGIN:
       ask->action = TAC_PLUS_AUTHEN_LOGIN;
       ask->authen_type = TAC_PLUS_AUTHEN_TYPE_ARAP;
       break;
    case TACACS_ASCII_CHPASS:
       ask->action = TAC_PLUS_AUTHEN_CHPASS;
       ask->authen_type = TAC_PLUS_AUTHEN_TYPE_ASCII;
       break;
  }
  /*
   * the length of fields in start packet
   * using without convertation ntohs or htons
   * (this is not clean in RFC)
   */
  /* username length */
  ask->user_len = strlen(username);
  ask->port_len = strlen(port);		/* length of port entry */
  ask->rem_addr_len = strlen(addr);	/* lenght of addr len */
  ask->data_len = strlen(data);		/* length of data */

  /* join data */
  if (strlen(username) > 0)
    strcpy(u, username); /* user */
  if (strlen(port) > 0)
    strcpy(p, port);     /* port */
  if (strlen(addr) > 0)
    strcpy(a, addr);     /* addr */

  if (type == TACACS_CHAP_LOGIN) {
     *d++ = 1;
     strcpy(d,data);
  }
  if (type == TACACS_ARAP_LOGIN || type == TACACS_PAP_LOGIN)
     strcpy(d,data);

  /* write_packet encripting datas */
  if (write_packet(session, buf)) return 1;
  return 0;
}


/* get REPLY reply (client function) */
/* return status packet and set variables
	return
		-1	FAILURE
Status:

   TAC_PLUS_AUTHEN_STATUS_PASS     := 0x01
   TAC_PLUS_AUTHEN_STATUS_FAIL     := 0x02
   TAC_PLUS_AUTHEN_STATUS_GETDATA  := 0x03
   TAC_PLUS_AUTHEN_STATUS_GETUSER  := 0x04
   TAC_PLUS_AUTHEN_STATUS_GETPASS  := 0x05
   TAC_PLUS_AUTHEN_STATUS_RESTART  := 0x06
   TAC_PLUS_AUTHEN_STATUS_ERROR    := 0x07
   TAC_PLUS_AUTHEN_STATUS_FOLLOW   := 0x21

*/
int tac_authen_get_reply(struct tac_session* session,
			    char* server, char* datas) {
   char *buf = read_packet(session);
   HDR *hdr = (HDR *)buf;	/* header */
   /* static datas */
   struct authen_reply *rep;
   /* server message */
   char *serv_msg;
   /* server datas */
   char *dat_pak;
   int mlen=0,dlen=0;

    if (session==NULL || buf==NULL)
	return 0;

   rep=(struct authen_reply *)(buf+TAC_PLUS_HDR_SIZE);
   serv_msg=(char *)(buf+TAC_PLUS_HDR_SIZE+TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE);
   dat_pak=(char *)(serv_msg + ntohs(rep->msg_len));

   bzero(server,sizeof(server));
   bzero(datas,sizeof(datas));

   /* fields length */
   mlen = ntohs(rep->msg_len);
   dlen = ntohs(rep->data_len);

   if (hdr->datalength != htonl(TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE +
	       mlen + dlen)) {
       tac_error("Invalid AUTHEN/REPLY packet, check keys.\n");
       return 0;
   }
   session->session_id = hdr->session_id;

   if (mlen > 0)
      strncpy(server,serv_msg,mlen);
   if (dlen > 0)
      strncpy(datas,dat_pak,dlen);

   return (rep->status);
}

/*
 *  Send CONTINUE packet
 *	  (client function)
 *  tac_authen_send_cont
 *	return
 *		1       SUCCESS
 *		0       FAILURE
 */
int
tac_authen_send_cont(struct tac_session* session, const char* user_msg,
			       const char* data) {
  char buf[TAC_BUF_LEN];
  HDR *hdr = (HDR *)buf;	/* header */
  /* datas */
  struct authen_cont *ask = (struct authen_cont *)(buf + TAC_PLUS_HDR_SIZE);
  /* packet */
  char *p = (char *)
    (buf + TAC_PLUS_HDR_SIZE + TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE);
  char *d = (char *)(p + strlen(user_msg));

  bzero(buf, sizeof(buf));	/* clean buffer */

  hdr->version = TAC_PLUS_VER_0;	/* set version */
  hdr->type = TAC_PLUS_AUTHEN;		/* packet type - authentication */
  hdr->seq_no = ++session->seq_no;	/* sequence number */
  /* set encryption */
  hdr->encryption = TAC_PLUS_CLEAR; /*TAC_PLUS_ENCRYPTED;*/
  hdr->session_id = session->session_id;	/* set session ID */
  /* packet length */
  hdr->datalength = htonl(TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE+strlen(user_msg)
			   + strlen(data));
  /* data length */
  ask->user_msg_len = htons(strlen(user_msg));
  ask->user_data_len = htons(strlen(data));

  /* set datas */
  if (strlen(user_msg) > 0)
    strcpy(p, user_msg);
  if (strlen(data) > 0)
    strcpy(d, data);

  /* send packet */
  if (write_packet(session, buf)) return 1;
  return 0;
}
/* -------------------------------------------------------- */
/*
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mod_tac.h"
*/

/*
   send the accounting REQUEST  (client function)
*/
int
tac_account_send_request(struct tac_session *session, const int flag,
	const int method, const int priv_lvl,const int authen_type,
	const int authen_service,const char *user, const char *port,
	char **avpair) {
   int i;
   char buf[TAC_BUF_LEN];
   char rem_addr[TAC_REM_ADDR_LEN];
   char name[TAC_NAME_LEN];
   HDR *hdr = (HDR *)buf;
   struct acct *acc = (struct acct *)(buf + TAC_PLUS_HDR_SIZE);
   char *lens=(char*)(buf+TAC_PLUS_HDR_SIZE+
		      TAC_ACCT_REQ_FIXED_FIELDS_SIZE);
   int arglens=0;

   /* this is addr */
   gethostname(name,sizeof(name));
   strncpy(rem_addr,tac_getipfromname(name),sizeof(rem_addr));

   bzero(buf, sizeof(buf));
   hdr->version = TAC_PLUS_VER_0;
   hdr->type = TAC_PLUS_ACCT;
   hdr->seq_no = ++session->seq_no;
   hdr->encryption = TAC_PLUS_CLEAR; /*TAC_PLUS_ENCRYPTED;*/
   hdr->session_id = session->session_id;

   for (i=0; avpair[i]!=NULL ; i++) {
      if (strlen(avpair[i])>255)    /* if lenght of AVP>255 set it to 255 */
	 avpair[i][255]=0;
      arglens += strlen(avpair[i]);
   }
   hdr->datalength = htonl(TAC_ACCT_REQ_FIXED_FIELDS_SIZE +
	i+strlen(user)+strlen(port)+strlen(rem_addr)+arglens);

   acc->flags = (unsigned char) flag;
   acc->authen_method = (unsigned char) method;
   acc->priv_lvl = (unsigned char) priv_lvl;
   acc->authen_type = (unsigned char) authen_type;
   acc->authen_service = (unsigned char) authen_service;
   acc->user_len=(unsigned char)strlen(user);
   acc->port_len=(unsigned char)strlen(port);
   acc->rem_addr_len = (unsigned char) strlen(rem_addr);
   acc->arg_cnt = (unsigned char) i;

   for (i=0; avpair[i]!=NULL ; i++) {
      *lens=(u_char)strlen(avpair[i]);
      lens=lens+1;
   }
   /* filling data */
   if (strlen(user)>0) {
      strcpy(lens,user);
      lens += strlen(user);
   }
   if (strlen(port)>0) {
      strcpy(lens,port);
      lens += strlen(port);
   }
   if (strlen(rem_addr)>0) {
      strcpy(lens,rem_addr);
      lens += strlen(rem_addr);
   }
   for (i=0; avpair[i]!=NULL ; i++) {
       strcpy(lens,avpair[i]);
       lens += (u_char)strlen(avpair[i]);
   }
   if (write_packet(session,buf)) return 1;
   return 0;
}


/*************************************************
    get the accounting REPLY (client function)
       1  SUCCESS
       0  FAILURE
**************************************************/
int
tac_account_get_reply(struct tac_session *session,
		    char *server_msg, char *data)
{
   int status;

   char *buf;
   buf=0;
   buf = read_packet(session);
   HDR *hdr = (HDR *)buf;
   struct acct_reply *acc = (struct acct_reply *)(buf + TAC_PLUS_HDR_SIZE);
   char *lens=(char*)(buf + TAC_PLUS_HDR_SIZE +
		      TAC_ACCT_REPLY_FIXED_FIELDS_SIZE);

   if (buf==NULL) return 0;
   /* some checks */
   if (hdr->type != TAC_PLUS_ACCT) {
      tac_error("This is not ACCOUNT request\n");
      return -1;
   }
   if (hdr->seq_no != 2) {
      tac_error("Error in sequence in ACCOUNT/REQUEST\n");
      return 0;
   }
   session->session_id = hdr->session_id;

   if (hdr->datalength != htonl(TAC_ACCT_REPLY_FIXED_FIELDS_SIZE+
      acc->msg_len + acc->data_len)) {
	tac_error("Error in ACCOUNT/REPLY packet, check keys\n");
	return 0;
   }
   status=acc->status;

   bzero(server_msg,sizeof(server_msg));
   strncpy(server_msg,lens,acc->msg_len);
   lens = lens + acc->msg_len;
   bzero(data,sizeof(data));
   strncpy(data,lens,acc->data_len);

   return status;
}
/* ---------------------------------------------------- */
