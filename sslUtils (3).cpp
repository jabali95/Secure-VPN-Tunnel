//============================================================================
// Name        : TP.cpp
// Author      : Huseyin Kayahan
// Version     : 1.0
// Copyright   : All rights reserved. Do not distribute.
// Description : TP Program
//============================================================================

#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <cstdio>
#include "sslUtils.h"
#include "commonUtils.h"
#include <iostream>

using namespace std;
BIO *bio_err = 0;
SSL_CTX * ctx;
SSL *ssl;
//Globals to share key, IV, and Random Bytes and update them
static unsigned char randombytes[48];
static unsigned char key[32];
static unsigned char iv[16];


int berr_exit(const char *string) {
BIO_printf(bio_err, "%s\n", string);
ERR_print_errors(bio_err);
exit(0);
}
//=============================================================================================

SSL *createSslObj(int role, int contChannel, char *certfile, char *keyfile, char *rootCApath ) {
	BIO *bio_socket;

	if(!bio_err){
		//Loads up the algorithms that will be used by OpenSSL
		SSL_library_init();

		//Load error strings for error reporting

		SSL_load_error_strings();

		/* An error write context */
		bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
	}


	// Server Side

	if(role == 0){
		//Structure to hold SSL information. A blueprint for an SSL object

		ctx = SSL_CTX_new(SSLv23_server_method());

		//Loads the identity certificate
		if(!(SSL_CTX_use_certificate_file(ctx, "/home/cdev/SSLCerts/srv.pem", SSL_FILETYPE_PEM))){
			berr_exit("Can’t load certificate file");
		}

		//Loads the private key of the identity certificate
		if(!(SSL_CTX_use_PrivateKey_file(ctx, "/home/cdev/SSLCerts/srv.key", SSL_FILETYPE_PEM))){
			berr_exit("Can’t read key file");
		}

		//Checks if the loaded public and private keys match
		if(!(SSL_CTX_check_private_key(ctx))) {
			berr_exit("public / private keys don't match");
		}
		//Loads the trust certificate store for given context
		//using 3rd argumant "Diractory" to the function after hashing it
		if(!(SSL_CTX_load_verify_locations(ctx, NULL,"/home/cdev/SSLCerts/CA" ))){
			berr_exit("Can’t locate CA list");
		}

		//Configure how the ccontex shall verify peer’s certificate
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);


		ssl = SSL_new(ctx);


		bio_socket = BIO_new_socket(contChannel, BIO_NOCLOSE);

		SSL_set_bio(ssl, bio_socket, bio_socket);
		if((SSL_accept(ssl))<=0){
			berr_exit("SSL accept error!");
		}
		//Server Accept to establish SSL Connection
		SSL_accept(ssl);

		//verify the Server Certificate Common Name
		X509 *peer;

		char CCN[256];


		if(SSL_get_verify_result(ssl)!=X509_V_OK){
			berr_exit("Certificate doesn't verify");
		}

		peer=SSL_get_peer_certificate(ssl);


		X509_NAME_get_text_by_NID (X509_get_subject_name(peer), NID_commonName, CCN, 256);
		if(strcasecmp(CCN,"TP Client ahmadj@kth.se")){
			berr_exit("Common name doesn't match host name");
		}

	}
	// Client Side
	if(role == 1){
		//Structure to hold SSL information. A blueprint for an SSL object

		ctx = SSL_CTX_new(SSLv23_client_method());

		//Loads the identity certificate
		if(!(SSL_CTX_use_certificate_file(ctx, "/home/cdev/SSLCerts/cli.pem", SSL_FILETYPE_PEM))){
			berr_exit("Can’t load certificate file");
		}

		//Loads the private key of the identity certificate
		if(!(SSL_CTX_use_PrivateKey_file(ctx, "/home/cdev/SSLCerts/cli.key", SSL_FILETYPE_PEM))){
			berr_exit("Can’t read key file");
		}


		//Checks if the loaded public and private keys match
		if(!(SSL_CTX_check_private_key(ctx))) {
			berr_exit("public / private keys don't match");
		}

		//Loads the trust certificate store for given context
		//using 3rd argumant "Diractory" to the function after hashing it
		if(!(SSL_CTX_load_verify_locations(ctx, NULL, "/home/cdev/SSLCerts/CA"))){
			berr_exit("Can’t locate CA list");
		}

		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
		ssl = SSL_new(ctx);
		//BIO *bio_socket;
		bio_socket = BIO_new_socket(contChannel, BIO_NOCLOSE);
		SSL_set_bio(ssl, bio_socket, bio_socket);

		//Client Accept to Connect to Server.
		SSL_connect(ssl);
		if(SSL_connect(ssl)<=0){
			berr_exit("SSL connect error");
		}


		//verify the Server Certificate Common Name
		X509 *peer;

		char CCN[256];


		if(SSL_get_verify_result(ssl)!=X509_V_OK){
			berr_exit("Certificate doesn't verify");
		}

		peer=SSL_get_peer_certificate(ssl);
		char *host = "TP Server ahmadj@kth.se";


		X509_NAME_get_text_by_NID (X509_get_subject_name(peer), NID_commonName, CCN, 256);
		if(strcasecmp(CCN,"TP Server ahmadj@kth.se")){
			berr_exit("Common name doesn't match host name");
		}

	}

	return ssl;
}

void dataChannelKeyExchange(int role, SSL *ssl) {

	//Server
	if(role==0) {
		//Creating random bytes, for KEY & IV
		unsigned char randomkeyiv[48];
		RAND_bytes(randomkeyiv, sizeof randomkeyiv);

		//Writing the KEY and IV to a global variable,
		//which will be sent over the data channel
		int i;
		for(i = 0; i < 48; i++) {
			randombytes[i] = randomkeyiv[i];
		}

		//Splitting 32 bytes from the generated random bytes.
		//Allocating them to KEY to be shared with other functions
		for(i = 0; i < 32; i++) {
			key[i] = randomkeyiv[i];
		}

		//Splitting 16 bytes from the generated random bytes.
		//Allocating them to IV to be shared with other functions

		i = 0;
		int j;
		for(j = 32; j < 48; j++) {
			iv[i] = randomkeyiv[j];
			i++;
		}

		//Writing 48 bytes to the data channel. TO be recevied by the CLient.
		SSL_write(ssl, randombytes, sizeof(randombytes));

	}
	//Client
	if(role==1)
	{

		//Reading the array generated from the server by data channel

		int x = SSL_read(ssl, randombytes, sizeof randombytes);

		//Exit if the size of the data transfered is less that 48
		if (	x!= sizeof randombytes){berr_exit("Could not transfer keys");}



		//Seperate the random bytes into the key and IV
		int i;
		for(i = 0; i < 32; i++) {
			key[i] = randombytes[i];
		}


		int j;
		i = 0;
		for(j = 32; j < 48; j++) {
			iv[i] = randombytes[j];
			i++;
		}
	}

}

//Error Handler for Encryption and Decryption
void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

int encrypt(unsigned char *plainText, int plainTextLen,
		unsigned char *cipherText) {

	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;

	/* Create and initialise the contex */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_EncryptUpdate(ctx, cipherText, &len, plainText, plainTextLen))
		handleErrors();
	ciphertext_len = len;

	/* Finalise the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */
	if(1 != EVP_EncryptFinal_ex(ctx, cipherText + len, &len))
		handleErrors();
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;

}

int decrypt(unsigned char *cipherText, int cipherTextLen,
		unsigned char *plainText) {
	//First packet sent is 1 byte, which islarger than  the block size, dropping this packet.
	if(cipherTextLen ==sizeof(signed char)){
		return 0;
	}

	EVP_CIPHER_CTX *ctx;

	int len=0;

	int plaintext_len=0;

	/* Create and initialise the contex */
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the decryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits */
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_DecryptUpdate(ctx, plainText, &len, cipherText, cipherTextLen))
		handleErrors();
	plaintext_len = len;

	/* Finalise the decryption. Further plaintext bytes may be written at
	 * this stage.
	 */
	if(1 != EVP_DecryptFinal_ex(ctx, plainText + len, &len)) handleErrors();
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;

}

