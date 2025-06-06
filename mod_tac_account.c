#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mod_tac.h"


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

   char *buf = read_packet(session);
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
