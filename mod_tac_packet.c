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
