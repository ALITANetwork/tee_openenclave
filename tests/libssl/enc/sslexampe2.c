
#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const char MimeBase64[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

static int DecodeMimeBase64[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 00-0F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 10-1F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, /* 20-2F */
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, /* 30-3F */
    -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, /* 40-4F */
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, /* 50-5F */
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, /* 60-6F */
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, /* 70-7F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 80-8F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 90-9F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* A0-AF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* B0-BF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* C0-CF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* D0-DF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* E0-EF */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1  /* F0-FF */
};

typedef union {
  struct {
#ifdef LITTLE_ENDIAN
    unsigned char c1, c2, c3;
#else
    unsigned char c3, c2, c1;
#endif
  };
  struct {
#ifdef LITTLE_ENDIAN
    unsigned int e1 : 6, e2 : 6, e3 : 6, e4 : 6;
#else
    unsigned int e4 : 6, e3 : 6, e2 : 6, e1 : 6;
#endif
  };
} BF;

void base64e(char *src, char *result, int length) {
  int i, j = 0;
  BF temp;

#ifdef LITTLE_ENDIAN
  for (i = 0; i < length; i = i + 3, j = j + 4) {
    temp.c3 = src[i];
    if ((i + 1) > length)
      temp.c2 = 0x00;
    else
      temp.c2 = src[i + 1];
    if ((i + 2) > length)
      temp.c1 = 0x00;
    else
      temp.c1 = src[i + 2];

    result[j] = MimeBase64[temp.e4];
    result[j + 1] = MimeBase64[temp.e3];
    result[j + 2] = MimeBase64[temp.e2];
    result[j + 3] = MimeBase64[temp.e1];

    if ((i + 2) > length)
      result[j + 2] = '=';
    if ((i + 3) > length)
      result[j + 3] = '=';
  }
#else
  for (i = 0; i < length; i = i + 3, j = j + 4) {
    temp.c1 = src[i];
    if ((i + 1) > length)
      temp.c2 = 0x00;
    else
      temp.c2 = src[i + 1];
    if ((i + 2) > length)
      temp.c3 = 0x00;
    else
      temp.c3 = src[i + 2];

    result[j] = MimeBase64[temp.e4];
    result[j + 1] = MimeBase64[temp.e3];
    result[j + 2] = MimeBase64[temp.e2];
    result[j + 3] = MimeBase64[temp.e1];

    if ((i + 2) > length)
      result[j + 2] = '=';
    if ((i + 3) > length)
      result[j + 3] = '=';
  }
#endif
}

void base64d(char *src, char *result, int *length) {
  int i, j = 0, src_length, blank = 0;
  BF temp;

  src_length = strlen(src);

#ifdef LITTLE_ENDIAN
  for (i = 0; i < src_length; i = i + 4, j = j + 3) {
    temp.e4 = DecodeMimeBase64[src[i]];
    temp.e3 = DecodeMimeBase64[src[i + 1]];
    if (src[i + 2] == '=') {
      temp.e2 = 0x00;
      blank++;
    } else
      temp.e2 = DecodeMimeBase64[src[i + 2]];
    if (src[i + 3] == '=') {
      temp.e1 = 0x00;
      blank++;
    } else
      temp.e1 = DecodeMimeBase64[src[i + 3]];

    result[j] = temp.c3;
    result[j + 1] = temp.c2;
    result[j + 2] = temp.c1;
  }
#else
  for (i = 0; i < src_length; i = i + 4, j = j + 3) {
    temp.e4 = DecodeMimeBase64[src[i]];
    temp.e3 = DecodeMimeBase64[src[i + 1]];
    if (src[i + 2] == '=') {
      temp.e2 = 0x00;
      blank++;
    } else
      temp.e2 = DecodeMimeBase64[src[i + 2]];
    if (src[i + 3] == '=') {
      temp.e1 = 0x00;
      blank++;
    } else
      temp.e1 = DecodeMimeBase64[src[i + 3]];

    result[j] = temp.c1;
    result[j + 1] = temp.c2;
    result[j + 2] = temp.c3;
  }
}
#endif
  *length = j - blank;
}

#define RESPONSE_LEN 10 * 1024
#define CHUNK_SIZE 2048
#define BUFF_SIZE 256
#define HTTP_GET_MESSAGE                                                       \
  "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (X11; Linux "        \
  "x86_64; rv:10.0.1) Gecko/20100101 Firefox/10.0.1\r\nAccept: "               \
  "image/png,image/*;q=0.8,*/*;q=0.5\r\nAccept-Language: "                     \
  "en-gb,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: " \
  "keep-alive\r\n\r\n"
#define INSTALL_FILEPATH "/tmp/devicemiddleware.deb"

int parseUpdateURL(char *full, int len, char *host, char *path) {
  int i;
  int host_cnt = 0;

  for (i = 0; i < len; i++) {
    host_cnt++;
    if (full[i] == '/')
      break;
  }

  if (host_cnt >= len)
    return -1;

  memcpy(host, full, host_cnt - 1);
  memcpy(path, &full[i], len - host_cnt + 1);

  return 0;
}

int hostname_to_ip(char *hostname, char *ip) {
  struct hostent *he;
  struct in_addr **addr_list;
  int i;

  if ((he = gethostbyname(hostname)) == NULL) {
    printf("gethostbyname error!\n");
    return -1;
  }

  addr_list = (struct in_addr **)he->h_addr_list;

  for (i = 0; addr_list[i] != NULL; i++) {
    strncpy(ip, inet_ntoa(*addr_list[i]), strlen(inet_ntoa(*addr_list[i])));
    return 0;
  }

  return -1;
}

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

int DownloadURLFile(char *url) {
  FILE *file = NULL;
  struct sockaddr_in server;
  int socket_desc;
  int header_len = 0;
  int total_len = 0;
  int received_len;
  int file_len;
  int header_end;
  char *p;
  char message[CHUNK_SIZE] = {0};
  char http_header[CHUNK_SIZE * 2] = {0};
  char server_reply[RESPONSE_LEN] = {0};
  char host[BUFF_SIZE] = {0};
  char path[BUFF_SIZE] = {0};
  char ip[32];

  BIO *certbio = NULL;
  BIO *outbio = NULL;
  X509 *cert = NULL;
  X509_NAME *certname = NULL;
  const SSL_METHOD *method;
  SSL_CTX *ctx;
  SSL *ssl;

  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  SSL_load_error_strings();

  /* ---------------------------------------------------------- *
   * Create the Input/Output BIO's. *
   * ---------------------------------------------------------- */
  certbio = BIO_new(BIO_s_file());
  outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* ---------------------------------------------------------- *
   * initialize SSL library and register algorithms *
   * ---------------------------------------------------------- */
  if (SSL_library_init() < 0)
    BIO_printf(outbio, "Could not initialize the OpenSSL library !\n");

  /* ---------------------------------------------------------- *
   * Set SSLv2 client hello, also announce SSLv3 and TLSv1 *
   * ---------------------------------------------------------- */
  method = SSLv23_client_method();

  /* ---------------------------------------------------------- *
   * Try to create a new SSL context *
   * ---------------------------------------------------------- */
  if ((ctx = SSL_CTX_new(method)) == NULL)
    BIO_printf(outbio, "Unable to create a new SSL context structure.\n");

  /* ---------------------------------------------------------- *
   * Disabling SSLv2 will leave v3 and TSLv1 for negotiation *
   * ---------------------------------------------------------- */
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

  /* ---------------------------------------------------------- *
   * Create new SSL connection state object *
   * ---------------------------------------------------------- */
  ssl = SSL_new(ctx);

  if (parseUpdateURL(url, strlen(url), host, path))
    return -1;
  printf("host: <%s>\npath: <%s>\n", host, path);

  // Create socket
  socket_desc = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_desc == -1) {
    printf("Could not create socket");
    return -1;
  }

  if (hostname_to_ip(host, ip))
    return -1;
  server.sin_addr.s_addr = inet_addr(ip);
  server.sin_family = AF_INET;
  server.sin_port = htons(443);

  // Connect to remote server
  printf(">>>>>>>>>> connect start\n");
  if (connect(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0) {
    printf("connect error");
    return -1;
  }
  printf(">>>>>>>>>> connect end\n");

  /* ---------------------------------------------------------- *
   * Attach the SSL session to the socket descriptor *
   * ---------------------------------------------------------- */
  SSL_set_fd(ssl, socket_desc);

  /* ---------------------------------------------------------- *
   * Try to SSL-connect here, returns 1 for success *
   * ---------------------------------------------------------- */
  if (SSL_connect(ssl) != 1)
    BIO_printf(outbio, "Error: Could not build a SSL session to: %s.\n", ip);
  else
    BIO_printf(outbio, "Successfully enabled SSL/TLS session to: %s.\n", ip);

  /* ---------------------------------------------------------- *
   * Get the remote certificate into the X509 structure *
   * ---------------------------------------------------------- */
  cert = SSL_get_peer_certificate(ssl);
  if (cert == NULL)
    BIO_printf(outbio, "Error: Could not get a certificate from: %s.\n", ip);
  else
    BIO_printf(outbio, "Retrieved the server's certificate from: %s.\n", ip);

  /* ---------------------------------------------------------- *
   * extract various certificate information *
   * -----------------------------------------------------------*/
  certname = X509_NAME_new();
  certname = X509_get_subject_name(cert);

  /* ---------------------------------------------------------- *
   * display the cert subject here *
   * -----------------------------------------------------------*/
  BIO_printf(outbio, "Displaying the certificate subject data:\n");
  X509_NAME_print_ex(outbio, certname, 0, 0);
  BIO_printf(outbio, "\n");

  // Send request
  snprintf(message, CHUNK_SIZE, HTTP_GET_MESSAGE, path, host);
  printf("message=\n%s\n========================\n", message);
  if (SSL_write(ssl, message, strlen(message)) < 0) {
    printf("Send failed");
    return -1;
  }
  // if( send(socket_desc , message , strlen(message) , 0) < 0) {
  // printf("Send failed");
  // return -1;
  //}
  remove(INSTALL_FILEPATH);
  file = fopen(INSTALL_FILEPATH, "ab");
  if (file == NULL) {
    printf("File could not opened");
    return -1;
  }

  // Download header
  memset(message, 0, CHUNK_SIZE);
  while (1) {
    // received_len = recv(socket_desc, message, CHUNK_SIZE - 1, 0);
    received_len = SSL_read(ssl, message, CHUNK_SIZE - 1);

    if (received_len < 0) {
      printf("recv failed");
      break;
    }

    if (header_len + received_len > CHUNK_SIZE * 2) {
      printf("header buffer overflow\n");
      return -1;
    }
    memcpy(&http_header[header_len], message, received_len);
    header_len += received_len;
    p = strstr(http_header, "\r\n\r\n");
    if (p != NULL) {
      break;
    }
  }

  printf("header received "
         "complete.\n=====================================\n%s\n==============="
         "===================\n",
         http_header);
  if (strstr(http_header, "404 Not Found") != NULL) {
    printf("Firmware File Not Found\n");
    return -1;
  }
  header_end = p - http_header + 4;
  p = strstr(http_header, "Content-Length");
  if (p == NULL) {
    printf("ERROR : Empty Content-Length\n");
    return -1;
  }

  p = strtok(strstr(http_header, "Content-Length"), " :\r\n");
  p = strtok(NULL, " :\r\n");
  file_len = atoi(p);
  fwrite(&http_header[header_end], (header_len - header_end), 1, file);
  file_len -= (header_len - header_end);

  // Download Content
  while (1) {
    // received_len = recv(socket_desc, server_reply, sizeof(server_reply), 0);
    received_len = SSL_read(ssl, server_reply, sizeof(server_reply));
    if (received_len < 0) {
      break;
    }
    if (total_len + received_len > file_len) {
      received_len = file_len - total_len;
    }
    total_len += received_len;
    fwrite(server_reply, received_len, 1, file);
    if (total_len >= file_len) {
      break;
    }
  }
  printf("filesize: <%d>\nreceived complete!!\n",
         total_len + (header_len - header_end));
  fclose(file);
  SSL_free(ssl);
  close(socket_desc);
  X509_free(cert);
  SSL_CTX_free(ctx);
  return 0;
}


int main(int argc, char *argv[]) 

{
   int retval = DownloadURLFile("oedownload.blob.core.windows.net/data/oelocalprovision.sh");

}   
