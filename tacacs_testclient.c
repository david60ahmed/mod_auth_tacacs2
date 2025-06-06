/* ====================================================================
 * Copyright (c) 1995-1997 The Apache Group.  All rights reserved.
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
 *    prior written permission.
 *
 * 5. Redistributions of any form whatsoever must retain the following
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
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */

/*
 * tacacs_testclient: command-line test interface for TACACS+ server
 *
 * GTS International  www.gts.com
 *   written by Jan Kratochvil <short@ucw.cz>
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <limits.h>

#include "mod_tac.h"

#ifdef USE_LOCAL_GETOPT
#include "getopt.h"
#else /* USE_LOCAL_GETOPT */
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif /* HAVE_GETOPT_H */
#endif /* USE_LOCAL_GETOPT */


const char version[]="This is tacacs_testclient, $Id: tacacs_testclient.c,v 1.2 2002/08/20 20:23:41 ryl Exp $\n";

#define DEFAULT_SERVER_HOSTNAME "127.0.0.1"
#define DEFAULT_SERVER_PORT     49
#define DEFAULT_SERVER_KEY      ""
#define DEFAULT_SERVER_TIMEOUT  3

#define REPLY_SERV_MSG_LEN (0x10000)
#define REPLY_DATA_MSG_LEN (0x10000)

typedef int sboolean;
typedef struct _Choice Choice;
typedef enum _Action Action;
typedef enum _MsgLevel MsgLevel;
typedef enum _TriBoolean TriBoolean;


#define LENGTH(arr) (sizeof((arr))/sizeof(*(arr)))
#define CLEAR(arr) memset((arr),0,sizeof((arr)))


/* Definitions from "glib":
 **************************/

#ifndef	FALSE
#define	FALSE	(0)
#endif

#ifndef	TRUE
#define	TRUE	(!FALSE)
#endif

/* Provide macros to feature the GCC function attribute.
 */
#if	__GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ > 4)
#define G_GNUC_PRINTF( format_idx, arg_idx )	\
  __attribute__((format (printf, format_idx, arg_idx)))
#define G_GNUC_NORETURN				\
  __attribute__((noreturn))
#else	/* !__GNUC__ */
#define G_GNUC_PRINTF( format_idx, arg_idx )
#define G_GNUC_NORETURN
#endif	/* !__GNUC__ */

/**************************
 */

enum _TriBoolean {
	TRIBOOLEAN_UNSET,
	TRIBOOLEAN_TRUE,
	TRIBOOLEAN_FALSE
	};

#define GETSTRING_STATIC_CHAR '^'
#define GETSTRING_STATIC_STRING "^"

static const char *argv0;
static const char *const *ArgV;

static sboolean switch_quiet;
static sboolean switch_verbose;

static const char *server_hostname=DEFAULT_SERVER_HOSTNAME;
static int         server_port    =DEFAULT_SERVER_PORT    ;
static const char *server_key     =DEFAULT_SERVER_KEY     ;
static int         server_timeout =DEFAULT_SERVER_TIMEOUT ;

static const char *client_portname="reported port name";
static const char *client_username="user name";
static const char *client_password="user password";
static const char *client_data    ="<authen type> dependent data";

static char *client_avpairs[256];
static unsigned client_avpairs_num=0;

static struct tac_session *session=NULL;

static TriBoolean exit_code=TRIBOOLEAN_UNSET;


enum _MsgLevel {
	ML_FATAL,
	ML_WARNING,
	ML_RESULT,
	ML_VERBOSE
	};

static void msg(MsgLevel msg_level,const char *fmt,...) G_GNUC_PRINTF(2,3);
static void msg(MsgLevel msg_level,const char *fmt,...)
{
va_list ap;
FILE *f;

	if ((msg_level==ML_VERBOSE && !switch_verbose)
	 || (msg_level==ML_RESULT  &&  switch_quiet  ))
		return;

	f=(msg_level==ML_FATAL || msg_level==ML_WARNING ? stderr : stdout);
	fprintf(f,"%s: ",argv0);
	if (msg_level==ML_WARNING)
		fputs("WARNING: ",f);
	va_start(ap,fmt);
	vfprintf(f,fmt,ap);
	va_end(ap);
	if (msg_level==ML_FATAL || msg_level==ML_WARNING)
		fputc('!',f);
	fputc('\n',f);
	if (msg_level==ML_FATAL)
		exit(EXIT_FAILURE);
}

static char *check_strdup(const char *string)
{
char *r;

	if ((r=strdup(string)))
		return(r);
	msg(ML_FATAL,"Unable to duplicate string \"%s\"",string);
	assert(0);
}

#define CHECK_TAC_FUNC(funcname,args...) \
		(check_tac_func(funcname(args), #funcname ))

static void check_tac_func(int result,const char *funcname)
{
	if (result==1)
		return;
	msg(ML_FATAL,"Error during %s function (returned %d)",funcname,result);
}


struct _Choice {
	const char *text;
	int value;
	};

#define CHOICE_HEADER(what) { GETSTRING_STATIC_STRING what , -1 /* value */ }

#define CHOOSE_TEXT(text,choices) \
		(choose((text),choice_##choices+1,LENGTH(choice_##choices)-1))
#define CMDLINE_CHOOSE(choices) \
		(choose(cmdline_getstring((const char **)&choice_##choices->text),choice_##choices+1,LENGTH(choice_##choices)-1))

static int choose(const char *text,const Choice *choices,unsigned choices_num)
{
unsigned choicei,matches;
long num;
char *endptr;

	assert(text);

	errno=0;
	num=strtol(text,&endptr,0 /* base */);
	if (!errno && (!endptr || !*endptr) && num>=INT_MIN && num<=INT_MAX)
		return(num);

	matches=0;
	for (choicei=0;choicei<choices_num;choicei++) {
const Choice *choice=choices+choicei;

		if (!strcasecmp(text,choice->text))
			return(choice->value);
		if (strncasecmp(text,choice->text,strlen(text)))
			continue;
		matches++;
		}
	if (matches==1) {
		for (choicei=0;choicei<choices_num;choicei++) {
const Choice *choice=choices+choicei;

			if (!strncasecmp(text,choice->text,strlen(text)))
				return(choice->value);
			}
		}
	if (matches)
		msg(ML_RESULT,"Choice text \"%s\" is ambiguous (%d matches), possible choices are:",text,matches);
	else
		msg(ML_RESULT,"Choice text \"%s\" not applicable, possible choices are:",text);
	for (choicei=0;choicei<choices_num;choicei++) {
const Choice *choice=choices+choicei;

		if (matches && strncasecmp(text,choice->text,strlen(text)))
			continue;
		msg(ML_RESULT,"\t%s\t(0x%X)",choice->text,choice->value);
		}
	msg(ML_FATAL,"Unable to resolve choice text \"%s\"",text);
	assert(0);
}

static void usage(void) G_GNUC_NORETURN;
static void usage(void)
{
	fprintf(stderr,"\
%s\
Debugging client for TACACS+ server:\n\
\n\
Usage: tacacs_testclient\n\
       [-s|--server <server IP=%s>[:<port=%d>]] [-p|--port <port=%d>]\n\
       [-k|--key <encryption key=\"%s\">] [-T|--timeout <timeout=%ds>]\n\
       [-q|--quiet] [-v|--verbose] [-h|--help] [-V|--version]\n\
       -> authen  <authen type> <port> <username> <password> [<data>]\n\
       -> author  <author method>\n\
                  <privilege lvl> <authen type> <authen service>\n\
                  <port> <username> [<av pair1> [<av pair2>...]]\n\
       -> account <account flags> <author method>\n\
                  <privilege lvl> <authen type> <authen service>\n\
                  <port> <username> [<av pair1> [<av pair2>...]]\n\
\n\
<account flags>:  MORE, START, STOP, WATCHDOG (','-separation allowed)\n\
<author method>:  NOT_SET, NONE, KRB5, LINE, ENABLE, LOCAL, TACACSPLUS, GUEST,\n\
                  RADIUS, KRB4, RCMD\n\
<privilege lvl>:  MAX(=15), ROOT(=15), USER(=1), MIN(=0)\n\
<authen type>:    ENABLE_REQUEST, ASCII_LOGIN, PAP_LOGIN, PAP_OUT, CHAP_LOGIN,\n\
                  CHAP_OUT, MSCHAP_LOGIN, MSCHAP_OUT, ARAP_LOGIN, ASCII_CHPASS\n\
<authen service>: NONE, LOGIN, ENABLE, PPP, ARAP, PT, RCMD, X25, NASI, FWPROXY\n\
\n\
  -q, --quiet\t\tDon't print any messages, only return exit code\n\
  -v, --verbose\t\tInform about communication operations\n\
  -h, --help\t\tPrint a summary of the options\n\
  -V, --version\t\tPrint the version number\n\
",version,DEFAULT_SERVER_HOSTNAME,DEFAULT_SERVER_PORT,DEFAULT_SERVER_PORT,
DEFAULT_SERVER_KEY,DEFAULT_SERVER_TIMEOUT);
	exit(EXIT_FAILURE);
}

const struct option longopts[]={
{"server"  ,1,0,'s'},
{"port"    ,1,0,'p'},
{"key"     ,1,0,'k'},
{"timeout" ,1,0,'t'},
{"quiet"   ,0,0,'q'},
{"verbose" ,0,0,'v'},
{"help"    ,0,0,'h'},
{"version" ,0,0,'V'},
{NULL      ,0,0, 0 }};

static void do_connect(void)
{
	assert(server_hostname);
	assert(server_key);
	assert(!session);

	msg(ML_VERBOSE,"Connecting to TAC server");
	if (!(session=tac_connect(server_hostname,server_timeout,server_key,server_port)))
		msg(ML_FATAL,"Unable to connect to TACACS server, host=%s:%d, key=\"%s\", timeout=%d seconds",
				server_hostname,server_port,server_key,server_timeout);
}

static void do_close(void)
{
	assert(session);
	msg(ML_VERBOSE,"Closing TAC session");
	tac_close(session);
	session=NULL;
}

static int cmdline_int(const char *string,int int_min,int int_max)
{
long num;
char *endptr;

	errno=0;
	num=strtol(string,&endptr,0 /* base */);
	if (errno || (endptr && *endptr))
		msg(ML_FATAL,"Error parsing command-line number \"%s\": error at \"%s\": %s\n",
				string,(!endptr ? "<unknown>" : endptr),strerror(errno));
	if (num<int_min || num>int_max)
		msg(ML_FATAL,"Command-line number \"%s\" out of range <%d..%d>",
				string,int_min,int_max);
	return(num);
}

#define CMDLINE_GETSTRING(where) (cmdline_getstring(&(where)))
static const char *cmdline_getstring(const char **where)
{
const char *what=*where;
const char *r;
int keep_static;

	assert(what);
	if ((keep_static=(*what==GETSTRING_STATIC_CHAR)))
		what++;
	if ((r=ArgV[optind++])) {
		if (!keep_static)
			*where=r;
		return(r);
		}
	msg(ML_FATAL,"Required string \"%s\" not found on command-line",what);
	assert(0);
}



static void cmdline_excessive(void)
{
int optind_orig;

	if (!ArgV[optind])
		return;
	for (optind_orig=optind;ArgV[optind];optind++)
		msg(ML_RESULT,"Excessive argument \"%s\" on command-line",ArgV[optind]);
	msg(ML_FATAL,"%d excessive arguments found on command-line",(optind-optind_orig));
}

static char reply_serv_msg[REPLY_SERV_MSG_LEN];
static char reply_data_msg[REPLY_DATA_MSG_LEN];

/* Workaround bug in mod_tac_authen.c/tac_authen_get_reply() which
 * doesn't '\0'-terminate the string.
 */
static void reply_prep_msg(void)
{
	CLEAR(reply_serv_msg);
	CLEAR(reply_data_msg);
	assert(!*client_avpairs);
	assert(!client_avpairs_num);
}


/* types of authentication */
static const Choice choice_authen_type[]={
	CHOICE_HEADER("types of authentication (=<authen type>)"),
	{ "enable_request", TACACS_ENABLE_REQUEST },
	{ "ascii_login",    TACACS_ASCII_LOGIN    },
	{ "pap_login",      TACACS_PAP_LOGIN      },
	{ "chap_login",     TACACS_CHAP_LOGIN     },
	{ "arap_login",     TACACS_ARAP_LOGIN     },
	{ "pap_out",        TACACS_PAP_OUT        },
	{ "chap_out",       TACACS_CHAP_OUT       },
	{ "ascii_arap_out", TACACS_ASCII_ARAP_OUT },
	{ "ascii_chpass",   TACACS_ASCII_CHPASS   },
	{ "ppp_chpass",     TACACS_PPP_CHPASS     },
	{ "arap_chpass",    TACACS_ARAP_CHPASS    },
	{ "mschap_login",   TACACS_MSCHAP_LOGIN   },
	{ "mschap_out",     TACACS_MSCHAP_OUT     },
	};

static int action_authen_get_reply(const char *for_what)
{
int authen_status;

	reply_prep_msg();
	if (-1==(authen_status=tac_authen_get_reply(session,reply_serv_msg,reply_data_msg)))
		msg(ML_FATAL,"Unable to receive reply for %s",for_what);
	msg(ML_RESULT,"Got reply for %s with status 0x%x=\"%s\"",
			for_what,authen_status,tac_print_authen_status(authen_status));
	msg(ML_VERBOSE,"... and serv_msg=\"%s\", data_msg=\"%s\"",
			reply_serv_msg,reply_data_msg);
	return(authen_status);
}

static void action_authen(void)
{
int authen_type;

	authen_type=CMDLINE_CHOOSE(authen_type);
	CMDLINE_GETSTRING(client_portname);
	CMDLINE_GETSTRING(client_username);
	CMDLINE_GETSTRING(client_password);
	if (ArgV[optind])
		CMDLINE_GETSTRING(client_data);
	else
		client_data="";
	cmdline_excessive();

	do_connect();
	msg(ML_VERBOSE,"Sending send_start authentication request");
	CHECK_TAC_FUNC(tac_authen_send_start,session,client_portname,client_username,authen_type,"" /* data */);
	msg(ML_VERBOSE,"Waiting for password sequel challenge");
	action_authen_get_reply("initial send_start");
	msg(ML_VERBOSE,"Sending send_cont password sequel");
	CHECK_TAC_FUNC(tac_authen_send_cont,session,client_password /* user_msg */,client_data /* data */);
	exit_code=(TAC_PLUS_AUTHEN_STATUS_PASS==action_authen_get_reply("send_cont")
	           ? TRIBOOLEAN_TRUE : TRIBOOLEAN_FALSE);
	msg(ML_VERBOSE,"Authentication phase finished");
	do_close();
}

/* methods of authorization */
static const Choice choice_author_method[]={
	CHOICE_HEADER("methods of authorization (=<author method>)"),
	{ "not_set",    TAC_PLUS_AUTHEN_METH_NOT_SET     },
	{ "none",       TAC_PLUS_AUTHEN_METH_NONE        },
	{ "krb5",       TAC_PLUS_AUTHEN_METH_KRB5        },
	{ "line",       TAC_PLUS_AUTHEN_METH_LINE        },
	{ "enable",     TAC_PLUS_AUTHEN_METH_ENABLE      },
	{ "local",      TAC_PLUS_AUTHEN_METH_LOCAL       },
	{ "tacacsplus", TAC_PLUS_AUTHEN_METH_TACACSPLUS  },
	{ "guest",      TAC_PLUS_AUTHEN_METH_GUEST       },
	{ "radius",     TAC_PLUS_AUTHEN_METH_RADIUS      },
	{ "krb4",       TAC_PLUS_AUTHEN_METH_KRB4        },
	{ "rcmd",       TAC_PLUS_AUTHEN_METH_RCMD        },
	};

/* priv_levels */
static const Choice choice_privilege_lvl[]={
	CHOICE_HEADER("privilege levels (=<privilege lvl>)"),
	{ "max",  TAC_PLUS_PRIV_LVL_MAX  },
	{ "root", TAC_PLUS_PRIV_LVL_ROOT },
	{ "user", TAC_PLUS_PRIV_LVL_USER },
	{ "min",  TAC_PLUS_PRIV_LVL_MIN  },
	};

/* authen services */
static const Choice choice_authen_service[]={
	CHOICE_HEADER("authentication services (=<authen service>)"),
	{ "none",        TAC_PLUS_AUTHEN_SVC_NONE       },
	{ "login",       TAC_PLUS_AUTHEN_SVC_LOGIN      },
	{ "enable",      TAC_PLUS_AUTHEN_SVC_ENABLE     },
	{ "ppp",         TAC_PLUS_AUTHEN_SVC_PPP        },
	{ "arap",        TAC_PLUS_AUTHEN_SVC_ARAP       },
	{ "pt",          TAC_PLUS_AUTHEN_SVC_PT         },
	{ "rcmd",        TAC_PLUS_AUTHEN_SVC_RCMD       },
	{ "x25",         TAC_PLUS_AUTHEN_SVC_X25        },
	{ "nasi",        TAC_PLUS_AUTHEN_SVC_NASI       },
	{ "fwproxy",     TAC_PLUS_AUTHEN_SVC_FWPROXY    },
	};

static void parse_trailing_author_account
		(int *author_methodp,int *privilege_lvlp,int *authen_typep,int *authen_servicep)
{
const char *avpair;

	assert(author_methodp);
	assert(privilege_lvlp);
	assert(authen_typep);
	assert(authen_servicep);

	*author_methodp =CMDLINE_CHOOSE(author_method);
	*privilege_lvlp =CMDLINE_CHOOSE(privilege_lvl );
	*authen_typep   =CMDLINE_CHOOSE(authen_type   );
	*authen_servicep=CMDLINE_CHOOSE(authen_service);

	CMDLINE_GETSTRING(client_portname);
	CMDLINE_GETSTRING(client_username);

	for (;(avpair=ArgV[optind]);optind++) {
size_t avpairl;

		if (!strpbrk(avpair,"=*"))
			msg(ML_WARNING,"AVpair is missing any of '=' or '*' as delimiter: %s",avpair);
		if (client_avpairs_num>=LENGTH(client_avpairs)-1) {
			msg(ML_WARNING,"Ignoring AVpair, maximal count %d reached: %s",client_avpairs_num,avpair);
			continue;
			}
		if ((avpairl=strlen(avpair))>255)
			msg(ML_WARNING,"AVpair longer than 255 chars (%lu chars), will be cut",(unsigned long)avpairl);
		client_avpairs[client_avpairs_num++]=check_strdup(avpair);
		}
	client_avpairs[client_avpairs_num]=NULL;

	/* cmdline_excessive();
	 * ^^^ not needed, ArgV is swallowed by AVpairs
	 */
}

static void count_client_avpairs(void)
{
	for (client_avpairs_num=0;client_avpairs_num<LENGTH(client_avpairs);client_avpairs_num++)
		if (!client_avpairs[client_avpairs_num])
			break;
	if (client_avpairs[client_avpairs_num])
		msg(ML_FATAL,"Internal local TAC error: returned # of AVpairs >%d",LENGTH(client_avpairs)-1);
}

static void free_client_avpairs(void)
{
	tac_free_avpairs(client_avpairs);
	*client_avpairs=NULL;
	client_avpairs_num=0;
}

static void action_author(void)
{
int author_method,privilege_lvl,authen_type,authen_service;
int author_status;
unsigned avpairi;

	parse_trailing_author_account(&author_method,&privilege_lvl,&authen_type,&authen_service);

	do_connect();
	msg(ML_VERBOSE,"Sending send_request authorization request");
	CHECK_TAC_FUNC(tac_author_send_request,session,
			author_method,privilege_lvl,authen_type,
			authen_service,client_username,client_portname,client_avpairs);
	free_client_avpairs();
	reply_prep_msg();
	msg(ML_VERBOSE,"Waiting for authorization response");
	if (-1==(author_status=tac_author_get_response(session,reply_serv_msg,reply_data_msg,client_avpairs)))
		msg(ML_FATAL,"Unable to receive reply for author_send_request");
	exit_code=(author_status==TAC_PLUS_AUTHOR_STATUS_PASS_ADD
	        || author_status==TAC_PLUS_AUTHOR_STATUS_PASS_REPL /* sent on exit code 2 w/filtered AVpairs */
					   ? TRIBOOLEAN_TRUE : TRIBOOLEAN_FALSE);
	count_client_avpairs();
	msg(ML_RESULT,"Got reply for author_send_request with status 0x%x=\"%s\"",
			author_status,tac_print_author_status(author_status));
	msg(ML_VERBOSE,"... and serv_msg=\"%s\", data_msg=\"%s\", AVpairs=%d",
			reply_serv_msg,reply_data_msg,client_avpairs_num);
	for (avpairi=0;avpairi<client_avpairs_num;avpairi++)
		msg(ML_VERBOSE,"\tAVpair[%u]: %s",avpairi,client_avpairs[avpairi]);
	free_client_avpairs();
	msg(ML_VERBOSE,"Authorization phase finished");
	do_close();
}


/* accounting flag */
static const Choice choice_account_flags[]={
	CHOICE_HEADER("accounting flags (=<account flags>)"),
	{ "more",     TAC_PLUS_ACCT_FLAG_MORE     },
	{ "start",    TAC_PLUS_ACCT_FLAG_START    },
	{ "stop",     TAC_PLUS_ACCT_FLAG_STOP     },
	{ "watchdog", TAC_PLUS_ACCT_FLAG_WATCHDOG },
	};

static void action_account(void)
{
char *flags_string,*next_flags;
int account_flags,author_method,privilege_lvl,authen_type,authen_service;
int account_status;

	flags_string=check_strdup(cmdline_getstring((const char **)&choice_account_flags->text));
	for (account_flags=0;flags_string && *flags_string;flags_string=next_flags) {
		if ((next_flags=strchr(flags_string,',')))
			*next_flags++='\0';
		account_flags|=CHOOSE_TEXT(flags_string,account_flags);
		}
	/* we should free() original "flags_string" here */
	parse_trailing_author_account(&author_method,&privilege_lvl,&authen_type,&authen_service);

	do_connect();
	msg(ML_VERBOSE,"Sending send_request accounting request");
	CHECK_TAC_FUNC(tac_account_send_request,session,account_flags,
			author_method,privilege_lvl,authen_type,
			authen_service,client_username,client_portname,client_avpairs);
	free_client_avpairs();
	reply_prep_msg();
	msg(ML_VERBOSE,"Waiting for accounting response");
	if (-1==(account_status=tac_account_get_reply(session,reply_serv_msg,reply_data_msg)))
		msg(ML_FATAL,"Unable to receive reply for author_send_request");
	exit_code=(account_status==TAC_PLUS_ACCT_STATUS_SUCCESS
					   ? TRIBOOLEAN_TRUE : TRIBOOLEAN_FALSE);
	msg(ML_RESULT,"Got reply for tac_account_send_request with status 0x%x=\"%s\"",
			account_status,tac_print_account_status(account_status));
	msg(ML_VERBOSE,"... and serv_msg=\"%s\", data_msg=\"%s\"",
			reply_serv_msg,reply_data_msg);
	msg(ML_VERBOSE,"Accounting phase finished");
	do_close();
}


enum _Action {
	ACTION_AUTHEN,
	ACTION_AUTHOR,
	ACTION_ACCOUNT,
	};

static const Choice choice_action[]={
	CHOICE_HEADER("action to invoke"),
	{ "authentication", ACTION_AUTHEN  },
	{ "authorization",  ACTION_AUTHOR  },
	{ "accounting",     ACTION_ACCOUNT },
	};

int main(int argc,char **argv)
{
char *s;
int optc;

	if ((s=strrchr(argv[0],'/')))
		argv0=s+1;
	else	
		argv0=argv[0];
	ArgV=(const char *const *)argv;

	msg(ML_VERBOSE,"Command-line parsing");

	while (-1!=(optc=getopt_long(argc,argv,"s:p:k:t:qvhV",longopts,NULL)))
	switch (optc) {
		case 's':
			server_hostname=check_strdup(optarg);
			if ((s=strchr(server_hostname,':'))) {
				*s='\0';
				optarg=s+1;
				/* FALLTHRU */
				}
			else
				break;

		case 'p':
			server_port=cmdline_int(optarg,1,0xFFFF);
			break;

		case 'k':
			server_key=optarg;
			break;

		case 't':
			server_timeout=cmdline_int(optarg,0,INT_MAX);
			break;

		case 'q':
			switch_quiet=TRUE;
			switch_verbose=FALSE;
			break;
		case 'v':
			switch_quiet=FALSE;
			switch_verbose=TRUE;
			break;
		case 'V':
			fprintf(stderr,version);
			exit(EXIT_FAILURE);
		default: /* also 'h' */
			usage();
			break;
		}

	assert(!session);
	switch (CMDLINE_CHOOSE(action)) {
		case ACTION_AUTHEN:  action_authen();  break;
		case ACTION_AUTHOR:  action_author();  break;
		case ACTION_ACCOUNT: action_account(); break;
		default: assert(0);
		}
	assert(!session);
	assert(!*client_avpairs);
	assert(!client_avpairs_num);
	assert(exit_code!=TRIBOOLEAN_UNSET);
	msg(ML_RESULT,"Gracefully terminating with code %s (%d)",
			(exit_code==TRIBOOLEAN_TRUE ? "EXIT_SUCCESS" : "EXIT_FAILURE"),
			(exit_code==TRIBOOLEAN_TRUE ?  EXIT_SUCCESS  :  EXIT_FAILURE ));

	return(exit_code==TRIBOOLEAN_TRUE ? EXIT_SUCCESS : EXIT_FAILURE);
}

/**********************************************************/
/* vi:ts=2:sw=2
 */
