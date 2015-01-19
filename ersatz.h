#ifndef _ersatz_h_
#define _ersatz_h_
#include <python2.7/Python.h>
#include <stdio.h>
#include <unistd.h>
/*
 * Global Vars
 */
extern PyObject *pyMod_pyhsm_base, *pyHSM;

/*
 * Error Codes
 */
enum py_status
{
	IMPORT_PYHSM_FAIL,
	IMPORT_PYHSM_OK,
	HSM_INIT_FAIL,
	HSM_INIT_OK,
	HSM_UNLOCK_FAIL,
	HSM_UNLOCK_OK,
	HSM_HMAC_FAIL,
	HSM_HMAC_OK,
	ERSATZ_INIT_OK,	
	ERSATZ_INIT_FAIL,
	ERSATZ_FIN_OK,
	ERSATZ_FIN_FAIL,
	ERSATZ_SALT_OK,
	ERSATZ_SALT_FAIL,
	ERSATZ_HASH_FAIL,
	ERSATZ_HASH_OK,
	ERSATZ_CLOSE_OK,
	ERSATZ_CORRECT_PW,
	ERSATZ_PW,
	ERSATZ_INCORRECT_PW
};

/*
 * Constants
 */
#define PYHSM_BASE "pyhsm.base"
#define YHSM "YHSM"
#define HSM_DEVICE "/dev/cuaU0"
#define UNLOCK "unlock"
#define HMAC_SHA1 "hmac_sha1"
#define KEY_HANDLER 0x1
#define EXECUTE  "execute"
#define GET_HASH "get_hash"
//16 chars
#define SALT_SIZE 16
#define HASH_SIZE 86
#define ERSATZ_DIGEST_LEN 106
#define HMAC_LEN 20
#define RAW_SALT_LEN 12
/*
 * Ersatz functions
 */
//import pyhsm into python
int py_import_pyhsm_base(void);
//initialize hsm
int py_hsm_init(void);
//unlock hsm
int py_hsm_unlock(void);
//HDF (HMAC_SHA1)
int py_hsm_hmac(char *input_str, char *out_hash);
//calculate ersatz salt
int py_ersatz_salt(char *password, char *ersatz_pw, char *out_salt);
//calc hash, produces $6$<SALT>$HASH
int py_ersatz_hash(char *password, char *ersatz_hash, char *out_hash);
//check password
int py_ersatz_pw_check(char *password, char *ersatz_payload);
int py_ersatz_init(void);
int py_ersatz_close(void);

char * ersatz_word_generator(void);

#endif
