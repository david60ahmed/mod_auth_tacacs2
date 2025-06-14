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


#ifndef __MOD_TAC_H__
#define __MOD_TAC_H__

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


#endif   /* __MOD_TAC_H__ */
