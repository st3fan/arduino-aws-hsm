// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.




// Configure your AWS Keys and Secrets here

struct AWSCredentials {
  const char *key;
  const char *secret;
};

AWSCredentials gAWSCredentials[] = {
    {"YOURKEYID", "YOURSECRETKEY"},
    {NULL, NULL}
};




// SHA1 / HMAC-SHA1 API (taken from http://gcc.gnu.org/onlinedocs/libiberty/)

typedef unsigned int sha1_uint32;

struct sha1_ctx
{
  sha1_uint32 A;
  sha1_uint32 B;
  sha1_uint32 C;
  sha1_uint32 D;
  sha1_uint32 E;

  sha1_uint32 total[2];
  sha1_uint32 buflen;
  sha1_uint32 buffer[32];
};


void sha1_init_ctx (struct sha1_ctx *ctx);
void sha1_process_block (const void *buffer, size_t len, struct sha1_ctx *ctx);
void sha1_process_bytes (const void *buffer, size_t len, struct sha1_ctx *ctx);
void *sha1_finish_ctx (struct sha1_ctx *ctx, void *resbuf);
void *sha1_read_ctx (const struct sha1_ctx *ctx, void *resbuf);
void *sha1_buffer (const char *buffer, size_t len, void *resblock);






// HSM Code Starts Here

const char *FindSecretForKey(const char *key)
{
  AWSCredentials* credentials = gAWSCredentials;
  while (credentials->key != NULL && credentials->secret != NULL) {
    if (strcmp(credentials->key, key) == 0) {
      return credentials->secret;
    }
    credentials++;
  }
  return NULL;
}

void setup()
{
  Serial.begin(115200); 
}

void loop()
{
  // Read a request from the serial port
    
  char buffer[8192];
  size_t length = Serial.readBytesUntil(0x00, buffer, sizeof(buffer) - 1);
  if (length > 0)
  {
    buffer[length] = 0x00;
    
    // We only respond to the SIGN-AWS-V2 command
    
    if (strncmp(buffer, "SIGN-AWS-V2 ", strlen("SIGN-AWS-V2 ")) != 0) {
      Serial.println("ERROR invalid-command");
      return;
    }

    char *message = buffer + strlen("SIGN-AWS-V2 ");
    
    // Parse the key out of the request
    
    
    char* p = strstr(message, "AWSAccessKeyId=");
    if (p == NULL) {
      Serial.println("ERROR awsaccesskeyid-not-found");
      return;      
    }
    
    p += strlen("AWSAccessKeyId=");
    
    char key[64 + 1];
    unsigned int key_length = 0;
    char *keyp = key;
    
    while (*p != 0x00 && *p != '&') {
      *keyp++ = *p++;
      if (++key_length > 64) {
        Serial.println("ERROR invalid-awsaccesskeyid");
        return;
      }
    }
    *keyp = 0x00;
    
    // See if we have a secret for this key
    
    const char *secret = FindSecretForKey(key);
    if (secret == NULL) {
      Serial.println("ERROR unknown-awsaccesskey");
      return;
    }
    
    // Sign the incoming request
    
    unsigned char digest[20];
    hmac_sha1(secret, strlen(secret), message, strlen(message), digest);
    
    // Print the result back as a hex digest
    
    Serial.print("SUCCESS ");
    for (int i = 0; i < sizeof(digest); i++) {
      if (digest[i] < 0x10) {
        Serial.print("0");
      }
      Serial.print(digest[i], HEX);
    }
    Serial.println("");
  }
}








// SHA1 / HMAC-SHA1 Code Starts Here

# define SWAP(n) (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

static const unsigned char fillbuf[64] = {
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


void sha1_init_ctx (struct sha1_ctx *ctx)
{
  ctx->A = 0x67452301;
  ctx->B = 0xefcdab89;
  ctx->C = 0x98badcfe;
  ctx->D = 0x10325476;
  ctx->E = 0xc3d2e1f0;

  ctx->total[0] = ctx->total[1] = 0;
  ctx->buflen = 0;
}

void *
sha1_read_ctx (const struct sha1_ctx *ctx, void *resbuf)
{
  ((sha1_uint32 *) resbuf)[0] = SWAP (ctx->A);
  ((sha1_uint32 *) resbuf)[1] = SWAP (ctx->B);
  ((sha1_uint32 *) resbuf)[2] = SWAP (ctx->C);
  ((sha1_uint32 *) resbuf)[3] = SWAP (ctx->D);
  ((sha1_uint32 *) resbuf)[4] = SWAP (ctx->E);

  return resbuf;
}

void *
sha1_finish_ctx (struct sha1_ctx *ctx, void *resbuf)
{
  /* Take yet unprocessed bytes into account.  */
  sha1_uint32 bytes = ctx->buflen;
  size_t size = (bytes < 56) ? 64 / 4 : 64 * 2 / 4;

  /* Now count remaining bytes.  */
  ctx->total[0] += bytes;
  if (ctx->total[0] < bytes)
    ++ctx->total[1];

  /* Put the 64-bit file length in *bits* at the end of the buffer.  */
  ctx->buffer[size - 2] = SWAP ((ctx->total[1] << 3) | (ctx->total[0] >> 29));
  ctx->buffer[size - 1] = SWAP (ctx->total[0] << 3);

  memcpy (&((char *) ctx->buffer)[bytes], fillbuf, (size - 2) * 4 - bytes);

  /* Process last bytes.  */
  sha1_process_block (ctx->buffer, size * 4, ctx);

  return sha1_read_ctx (ctx, resbuf);
}

/* Compute SHA1 message digest for LEN bytes beginning at BUFFER.  The
   result is always in little endian byte order, so that a byte-wise
   output yields to the wanted ASCII representation of the message
   digest.  */
void *
sha1_buffer (const char *buffer, size_t len, void *resblock)
{
  struct sha1_ctx ctx;

  /* Initialize the computation context.  */
  sha1_init_ctx (&ctx);

  /* Process whole buffer but last len % 64 bytes.  */
  sha1_process_bytes (buffer, len, &ctx);

  /* Put result in desired memory area.  */
  return sha1_finish_ctx (&ctx, resblock);
}

void
sha1_process_bytes (const void *buffer, size_t len, struct sha1_ctx *ctx)
{
  /* When we already have some bits in our internal buffer concatenate
     both inputs first.  */
  if (ctx->buflen != 0)
    {
      size_t left_over = ctx->buflen;
      size_t add = 128 - left_over > len ? len : 128 - left_over;

      memcpy (&((char *) ctx->buffer)[left_over], buffer, add);
      ctx->buflen += add;

      if (ctx->buflen > 64)
	{
	  sha1_process_block (ctx->buffer, ctx->buflen & ~63, ctx);

	  ctx->buflen &= 63;
	  /* The regions in the following copy operation cannot overlap.  */
	  memcpy (ctx->buffer,
		  &((char *) ctx->buffer)[(left_over + add) & ~63],
		  ctx->buflen);
	}

      buffer = (const char *) buffer + add;
      len -= add;
    }

  /* Process available complete blocks.  */
  if (len >= 64)
    {
#if !_STRING_ARCH_unaligned
# define alignof(type) offsetof (struct { char c; type x; }, x)
# define UNALIGNED_P(p) (((size_t) p) % alignof (sha1_uint32) != 0)
      if (UNALIGNED_P (buffer))
	while (len > 64)
	  {
	    sha1_process_block (memcpy (ctx->buffer, buffer, 64), 64, ctx);
	    buffer = (const char *) buffer + 64;
	    len -= 64;
	  }
      else
#endif
	{
	  sha1_process_block (buffer, len & ~63, ctx);
	  buffer = (const char *) buffer + (len & ~63);
	  len &= 63;
	}
    }

  /* Move remaining bytes in internal buffer.  */
  if (len > 0)
    {
      size_t left_over = ctx->buflen;

      memcpy (&((char *) ctx->buffer)[left_over], buffer, len);
      left_over += len;
      if (left_over >= 64)
	{
	  sha1_process_block (ctx->buffer, 64, ctx);
	  left_over -= 64;
	  memcpy (ctx->buffer, &ctx->buffer[16], left_over);
	}
      ctx->buflen = left_over;
    }
}

/* --- Code below is the primary difference between md5.c and sha1.c --- */

/* SHA1 round constants */
#define K1 0x5a827999
#define K2 0x6ed9eba1
#define K3 0x8f1bbcdc
#define K4 0xca62c1d6

/* Round functions.  Note that F2 is the same as F4.  */
#define F1(B,C,D) ( D ^ ( B & ( C ^ D ) ) )
#define F2(B,C,D) (B ^ C ^ D)
#define F3(B,C,D) ( ( B & C ) | ( D & ( B | C ) ) )
#define F4(B,C,D) (B ^ C ^ D)

/* Process LEN bytes of BUFFER, accumulating context into CTX.
   It is assumed that LEN % 64 == 0.
   Most of this code comes from GnuPG's cipher/sha1.c.  */

void
sha1_process_block (const void *buffer, size_t len, struct sha1_ctx *ctx)
{
  const sha1_uint32 *words = (const sha1_uint32*) buffer;
  size_t nwords = len / sizeof (sha1_uint32);
  const sha1_uint32 *endp = words + nwords;
  sha1_uint32 x[16];
  sha1_uint32 a = ctx->A;
  sha1_uint32 b = ctx->B;
  sha1_uint32 c = ctx->C;
  sha1_uint32 d = ctx->D;
  sha1_uint32 e = ctx->E;

  /* First increment the byte count.  RFC 1321 specifies the possible
     length of the file up to 2^64 bits.  Here we only compute the
     number of bytes.  Do a double word increment.  */
  ctx->total[0] += len;
  if (ctx->total[0] < len)
    ++ctx->total[1];

#define rol(x, n) (((x) << (n)) | ((sha1_uint32) (x) >> (32 - (n))))

#define M(I) ( tm =   x[I&0x0f] ^ x[(I-14)&0x0f] \
		    ^ x[(I-8)&0x0f] ^ x[(I-3)&0x0f] \
	       , (x[I&0x0f] = rol(tm, 1)) )

#define R(A,B,C,D,E,F,K,M)  do { E += rol( A, 5 )     \
				      + F( B, C, D )  \
				      + K	      \
				      + M;	      \
				 B = rol( B, 30 );    \
			       } while(0)

  while (words < endp)
    {
      sha1_uint32 tm;
      int t;
      for (t = 0; t < 16; t++)
	{
	  x[t] = SWAP (*words);
	  words++;
	}

      R( a, b, c, d, e, F1, K1, x[ 0] );
      R( e, a, b, c, d, F1, K1, x[ 1] );
      R( d, e, a, b, c, F1, K1, x[ 2] );
      R( c, d, e, a, b, F1, K1, x[ 3] );
      R( b, c, d, e, a, F1, K1, x[ 4] );
      R( a, b, c, d, e, F1, K1, x[ 5] );
      R( e, a, b, c, d, F1, K1, x[ 6] );
      R( d, e, a, b, c, F1, K1, x[ 7] );
      R( c, d, e, a, b, F1, K1, x[ 8] );
      R( b, c, d, e, a, F1, K1, x[ 9] );
      R( a, b, c, d, e, F1, K1, x[10] );
      R( e, a, b, c, d, F1, K1, x[11] );
      R( d, e, a, b, c, F1, K1, x[12] );
      R( c, d, e, a, b, F1, K1, x[13] );
      R( b, c, d, e, a, F1, K1, x[14] );
      R( a, b, c, d, e, F1, K1, x[15] );
      R( e, a, b, c, d, F1, K1, M(16) );
      R( d, e, a, b, c, F1, K1, M(17) );
      R( c, d, e, a, b, F1, K1, M(18) );
      R( b, c, d, e, a, F1, K1, M(19) );
      R( a, b, c, d, e, F2, K2, M(20) );
      R( e, a, b, c, d, F2, K2, M(21) );
      R( d, e, a, b, c, F2, K2, M(22) );
      R( c, d, e, a, b, F2, K2, M(23) );
      R( b, c, d, e, a, F2, K2, M(24) );
      R( a, b, c, d, e, F2, K2, M(25) );
      R( e, a, b, c, d, F2, K2, M(26) );
      R( d, e, a, b, c, F2, K2, M(27) );
      R( c, d, e, a, b, F2, K2, M(28) );
      R( b, c, d, e, a, F2, K2, M(29) );
      R( a, b, c, d, e, F2, K2, M(30) );
      R( e, a, b, c, d, F2, K2, M(31) );
      R( d, e, a, b, c, F2, K2, M(32) );
      R( c, d, e, a, b, F2, K2, M(33) );
      R( b, c, d, e, a, F2, K2, M(34) );
      R( a, b, c, d, e, F2, K2, M(35) );
      R( e, a, b, c, d, F2, K2, M(36) );
      R( d, e, a, b, c, F2, K2, M(37) );
      R( c, d, e, a, b, F2, K2, M(38) );
      R( b, c, d, e, a, F2, K2, M(39) );
      R( a, b, c, d, e, F3, K3, M(40) );
      R( e, a, b, c, d, F3, K3, M(41) );
      R( d, e, a, b, c, F3, K3, M(42) );
      R( c, d, e, a, b, F3, K3, M(43) );
      R( b, c, d, e, a, F3, K3, M(44) );
      R( a, b, c, d, e, F3, K3, M(45) );
      R( e, a, b, c, d, F3, K3, M(46) );
      R( d, e, a, b, c, F3, K3, M(47) );
      R( c, d, e, a, b, F3, K3, M(48) );
      R( b, c, d, e, a, F3, K3, M(49) );
      R( a, b, c, d, e, F3, K3, M(50) );
      R( e, a, b, c, d, F3, K3, M(51) );
      R( d, e, a, b, c, F3, K3, M(52) );
      R( c, d, e, a, b, F3, K3, M(53) );
      R( b, c, d, e, a, F3, K3, M(54) );
      R( a, b, c, d, e, F3, K3, M(55) );
      R( e, a, b, c, d, F3, K3, M(56) );
      R( d, e, a, b, c, F3, K3, M(57) );
      R( c, d, e, a, b, F3, K3, M(58) );
      R( b, c, d, e, a, F3, K3, M(59) );
      R( a, b, c, d, e, F4, K4, M(60) );
      R( e, a, b, c, d, F4, K4, M(61) );
      R( d, e, a, b, c, F4, K4, M(62) );
      R( c, d, e, a, b, F4, K4, M(63) );
      R( b, c, d, e, a, F4, K4, M(64) );
      R( a, b, c, d, e, F4, K4, M(65) );
      R( e, a, b, c, d, F4, K4, M(66) );
      R( d, e, a, b, c, F4, K4, M(67) );
      R( c, d, e, a, b, F4, K4, M(68) );
      R( b, c, d, e, a, F4, K4, M(69) );
      R( a, b, c, d, e, F4, K4, M(70) );
      R( e, a, b, c, d, F4, K4, M(71) );
      R( d, e, a, b, c, F4, K4, M(72) );
      R( c, d, e, a, b, F4, K4, M(73) );
      R( b, c, d, e, a, F4, K4, M(74) );
      R( a, b, c, d, e, F4, K4, M(75) );
      R( e, a, b, c, d, F4, K4, M(76) );
      R( d, e, a, b, c, F4, K4, M(77) );
      R( c, d, e, a, b, F4, K4, M(78) );
      R( b, c, d, e, a, F4, K4, M(79) );

      a = ctx->A += a;
      b = ctx->B += b;
      c = ctx->C += c;
      d = ctx->D += d;
      e = ctx->E += e;
    }
}


static const unsigned int HMAC_SHA1_BLOCKSIZE = 64;

void *
hmac_sha1(const char *key_buffer, size_t key_length, const char *msg_buffer, size_t msg_length, void *result)
{
  // Initialize the key with zeros

  unsigned char key[HMAC_SHA1_BLOCKSIZE];
  for (unsigned int i = 0; i < HMAC_SHA1_BLOCKSIZE; i++) {
    key[i] = 0;
  }

  // If the key is too long, replace it with a SHA1 hash. Otherwise just copy it. It will be padded with zeros.
  
  if (key_length > HMAC_SHA1_BLOCKSIZE) {
    // TODO
  } else {
    for (unsigned int i = 0; i < key_length; i++) {
      key[i] = key_buffer[i];
    }
  }

  // Calculate o and i. Both are B long 
  
  unsigned char o_key_pad[HMAC_SHA1_BLOCKSIZE];
  unsigned char i_key_pad[HMAC_SHA1_BLOCKSIZE];
  
  for (unsigned int i = 0; i < HMAC_SHA1_BLOCKSIZE; i++) {
    i_key_pad[i] = 0x36 ^ key[i];
    o_key_pad[i] = 0x5c ^ key[i];
  }

  // hash of i_key_pad + msg

  unsigned char tmp[20];
  
  struct sha1_ctx ctx;
  
  sha1_init_ctx (&ctx);
  sha1_process_bytes(i_key_pad, HMAC_SHA1_BLOCKSIZE, &ctx);
  sha1_process_bytes(msg_buffer, msg_length, &ctx);
  sha1_finish_ctx(&ctx, tmp);
  
  // hash of o_key_pad + tmp
  
  sha1_init_ctx (&ctx);
  sha1_process_bytes(o_key_pad, HMAC_SHA1_BLOCKSIZE, &ctx);
  sha1_process_bytes(tmp, 20, &ctx);
  sha1_finish_ctx(&ctx, result);

  return result;  
}


