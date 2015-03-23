/*-
 * All rights reserved.
 * Copyright (c) 2002-2003 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * Portions of this software was developed for the FreeBSD Project by
 * ThinkSec AS and NAI Labs, the Security Research Division of Network
 * Associates, Inc.  under DARPA/SPAWAR contract N66001-01-C-8035
 * ("CBOSS"), as part of the DARPA CHATS research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


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
#define HSM_DEVICE "/dev/cuaU1"
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

//colors for warning msgs
//from stack overflow color-text-in-terminal-application-in-unix
#define KGRN "\x1B[32m"
#define KRED "\x1B[31m"
#define RESET "\033[0m"


/* configs */
#define DISP_ERSATZ_WARNING 1
#define ERSATZ_WARNING_BANNER "-----=====ERSATZ PASSWORD DETECTED=====-----\n"
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
