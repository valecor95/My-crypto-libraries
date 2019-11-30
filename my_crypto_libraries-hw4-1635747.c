#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>
#include <time.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/modes.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>

// gcc -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include my_crypto_libraries-hw4-1635747.c
// -o my_crypto_libraries-hw4-1635747  -lssl -lcrypto -lm -lwolfssl

void handleErrors(void){
    ERR_print_errors_fp(stderr);
    abort();
}

/*********************************************************************** WolfSSL FUNCTION ***********************************************************************/
void WolfSSL_AesEncrypt(byte* plaintext, int plaintext_len, byte* key, byte* iv, byte* ciphertext){
    Aes aes;
    // sets key
    if (wc_AesSetKey(&aes, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION) != 0) handleErrors();
    // encrypts the message to the output based on input length + padding
    if (wc_AesCbcEncrypt(&aes, ciphertext, plaintext, plaintext_len) != 0) handleErrors();
}

int WolfSSL_AesDecrypt(byte* ciphertext, int ciphertext_len, byte* key, byte* iv, byte* plaintext){
    Aes aes;
    // sets key
    if (wc_AesSetKey(&aes, key, AES_BLOCK_SIZE, iv, AES_DECRYPTION) != 0) handleErrors();
    // decrypts the message to output based on input length
    if (wc_AesCbcDecrypt(&aes, plaintext, ciphertext, ciphertext_len) != 0) handleErrors();

    return 0;
}

/*********************************************************************** OpenSSL FUNCTION ***********************************************************************/
void OpenSSL_AesEncrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext){
    EVP_CIPHER_CTX *ctx;

    int len, ciphertext_len;
    int iv_len = strlen((char*) iv);

    //Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    //Initialise the encryption operation.
  	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();
    //Provide the message to be encrypted, and obtain the encrypted output. EVP_EncryptUpdate can be called multiple times if necessary
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)){ handleErrors();} ciphertext_len = len;
    //Finalise the encryption. Further ciphertext bytes may be written at this stage.
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)){ handleErrors();} ciphertext_len += len;
    //Clean up
    EVP_CIPHER_CTX_free(ctx);
}

void OpenSSL_AesDecrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext){
    EVP_CIPHER_CTX *ctx;

    int len, plaintext_len, ret;
    int iv_len = 16;

    //Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    //Initialise the decryption operation.
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();
    //Provide the message to be decrypted, and obtain the plaintext output. EVP_DecryptUpdate can be called multiple times if necessary.
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)){ handleErrors();} plaintext_len = len;
    //Finalise the decryption. Further plaintext bytes may be written at this stage.
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)){ handleErrors();} plaintext_len += len;
    //Clean up
    EVP_CIPHER_CTX_free(ctx);
}




int main (int argc, char **argv)
{
  if(argc < 2){
    printf("Usage ./galois_counter_mode filename\n");
    exit(1);
  }

	// Message to be encrypted 
	/*****************************************************************************************************************************/
	unsigned char* in;													// Structure for input file
  unsigned char* tmp;													// Structure for input file
	unsigned long in_size;
	// in  <-  file in input
	printf("*** READING FILE ***\n");

	char* filename = argv[1];

	int fd = open(filename, O_RDONLY, (mode_t)0666);
	int fdr = fd;
	if(fd == -1){
    fprintf(stderr, "Error in open file\n");
    exit(1);
  }
	in_size = lseek(fd, 0, SEEK_END);
	in = malloc(sizeof(char)*in_size);
	in = (unsigned char*) mmap(0, in_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fdr, 0);
	close(fdr);

	printf("Length of file = %ld Bytes\n", in_size);
	printf("*** END READING FILE ***\n\n");
	/*****************************************************************************************************************************/

  unsigned char* key_256 = malloc(sizeof(char)*32);
	unsigned char* iv_128 = malloc(sizeof(char)*16);
	unsigned char* aux_iv_128 = malloc(sizeof(char)*16);
	clock_t start, end;																				                     // clock for timing
	double enc_time = 0, dec_time = 0;


	printf("********************************************* Cipher Algorithm: AES with CBC mode *********************************************\n\n");
	RAND_bytes(key_256, 32);         // pseudo-random key
	RAND_bytes(iv_128, 16);          // pseudo-random iv

  int enc_out_size = ((in_size/AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
	unsigned char* enc_out = calloc(enc_out_size, sizeof(char));									// Structure for encryption output
	int dec_out_size = enc_out_size;
	unsigned char* dec_out = calloc(dec_out_size, sizeof(char));									// Structure for decryption output

  printf("	+++++++++++++++++++++  Libraries: OpenSSL\n");
	printf("	ENCRYPTING");
	memcpy(aux_iv_128, iv_128, AES_BLOCK_SIZE);
	start = clock();
	OpenSSL_AesEncrypt(in, in_size, key_256, aux_iv_128, enc_out);
	end = clock();
	enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("  Time ===> %lf\n", enc_time);

	printf("	DECRYPTING");
	memcpy(aux_iv_128, iv_128, AES_BLOCK_SIZE);
	start = clock();
	OpenSSL_AesDecrypt(enc_out, enc_out_size, key_256, aux_iv_128, dec_out);
	end = clock();
	dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("  Time ===> %lf\n", dec_time);
	printf("	SPEED RATIO ==========> %lf\n\n", (enc_time/dec_time));



  printf("	+++++++++++++++++++++  Libraries: WolfSSL\n");
  int pad = enc_out_size - in_size;

	printf("	ENCRYPTING");
	memcpy(aux_iv_128, iv_128, AES_BLOCK_SIZE);
	start = clock();
	WolfSSL_AesEncrypt(in, in_size + pad, key_256, aux_iv_128, enc_out);
	end = clock();
	enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("  Time ===> %lf\n", enc_time);

	printf("	DECRYPTING");
	memcpy(aux_iv_128, iv_128, AES_BLOCK_SIZE);
	start = clock();
	WolfSSL_AesDecrypt(enc_out, enc_out_size, key_256, aux_iv_128, dec_out);
	end = clock();
	dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("  Time ===> %lf\n", dec_time);
	printf("	SPEED RATIO ==========> %lf\n\n", (enc_time/dec_time));

/*
  // WRITE ON FILE
  FILE * fp;
  int i;
  fp = fopen ("ciphertext.enc","w");
  for(i = 0; i < in_size; i++) fprintf (fp, "%c", (char)dec_out[i]);
  fclose (fp);
*/

/*
  //OUTPUT CHECKING
  printf("INPUT is:\n");
  BIO_dump_fp (stdout, (const char *)in, in_size);
  printf("Ciphertext is:\n");
  BIO_dump_fp (stdout, (const char *)enc_out, enc_out_size);
  printf("plaintext is:\n");
  BIO_dump_fp (stdout, (const char *)dec_out, enc_out_size);
*/

  free(enc_out);
	free(dec_out);
  free(key_256);
	free(iv_128);
  free(aux_iv_128);

  return 0;
}
