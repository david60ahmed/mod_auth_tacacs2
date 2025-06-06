/*
 * authorization
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mod_tac.h"


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
