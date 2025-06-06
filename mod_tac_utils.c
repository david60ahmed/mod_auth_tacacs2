#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdarg.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "mod_tac.h"

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
