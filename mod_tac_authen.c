/*
 *   AUTHENTICATION
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mod_tac.h"


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
