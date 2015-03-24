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

#include "ersatz.h"
#include "ersatz_words.h"
#include <time.h>
#include <stdlib.h>
#include <gperftools/profiler.h>
#include <assert.h>
#define b64_ntop __b64_ntop
#define b64_pton __b64_pton

int b64_ntop(unsigned const char *src, 
			 size_t srclen, char *target, 
			 size_t targetsize);
int b64_pton(unsigned const char *src, unsigned char *target, 
			 size_t targetsize);
PyObject *pyMod_pyhsm_base, *pyHSM;

/*
 * 
 */
int py_import_pyhsm_base(void)
{
	PyObject *pyName;
	pyName = PyString_FromString(PYHSM_BASE);
    pyMod_pyhsm_base = PyImport_Import(pyName);
	//dereference the string "pyhsm.base" in python (no longer needed)
    Py_DECREF(pyName);
	if(pyMod_pyhsm_base == NULL)
		return IMPORT_PYHSM_FAIL;
	else
		return IMPORT_PYHSM_OK;
}

int py_hsm_init(void)
{
	PyObject *pyFunc_yhsm, *pyArgs, *pyStr_hsm_dev;
	pyFunc_yhsm = PyObject_GetAttrString(pyMod_pyhsm_base, YHSM);
 
	if (pyFunc_yhsm && PyCallable_Check(pyFunc_yhsm))
	{
        pyArgs = PyTuple_New(1);
        pyStr_hsm_dev = PyString_FromString(HSM_DEVICE);
        PyTuple_SetItem(pyArgs, 0, pyStr_hsm_dev);
        pyHSM = PyObject_CallObject(pyFunc_yhsm, pyArgs);
        Py_DECREF(pyArgs);

		return HSM_INIT_OK;
	}
	else
		return HSM_INIT_FAIL;
}

int py_hsm_unlock(void)
{
	PyObject *pyFunc_unlock = PyObject_GetAttrString(pyHSM, UNLOCK);
	
	if(pyFunc_unlock && PyCallable_Check(pyFunc_unlock))
	{
		PyObject_CallObject(pyFunc_unlock, NULL);
		return HSM_UNLOCK_OK;
	}
	else
		return HSM_UNLOCK_FAIL;
}

int py_ersatz_init(void)
{
	Py_Initialize();
    int ret = py_import_pyhsm_base();
    if(ret != IMPORT_PYHSM_OK)
    {
        PyErr_Print();
        return ret;
    }

    ret = py_hsm_init();
    if(ret != HSM_INIT_OK)
    {
        PyErr_Print();
        return ret;
    }

    ret = py_hsm_unlock();
    if(ret != HSM_UNLOCK_OK)
    {
        PyErr_Print();
        return ret;
    }

	return ERSATZ_INIT_OK;
}

int py_ersatz_close(void)
{
	/* TODO: close the fob */
	Py_Finalize();
	return ERSATZ_CLOSE_OK;
}

int py_hsm_hmac(char *input_str, char *out_hash)
{
	PyObject *pyFunc_hmac = PyObject_GetAttrString(pyHSM, HMAC_SHA1);
	PyObject *pyArgs_hmac, *pyStr_input, *pyInt_key_handler;
	PyObject *tmp;
	if(pyFunc_hmac && PyCallable_Check(pyFunc_hmac))
	{
		//ProfilerStart("/tmp/hsm_hmac.log");
		pyArgs_hmac = PyTuple_New(2);
        pyStr_input = PyString_FromString(input_str);
        pyInt_key_handler = PyInt_FromLong(KEY_HANDLER);
		PyTuple_SetItem(pyArgs_hmac, 0, pyInt_key_handler);
		PyTuple_SetItem(pyArgs_hmac, 1, pyStr_input);
		tmp=PyObject_CallObject(pyFunc_hmac, pyArgs_hmac);
		
		//exec
		pyFunc_hmac = PyObject_GetAttrString(tmp, EXECUTE);
		tmp=PyObject_CallObject(pyFunc_hmac, NULL);
		
		pyFunc_hmac = PyObject_GetAttrString(tmp, GET_HASH);
		tmp = PyObject_CallObject(pyFunc_hmac, NULL);
		char *buff = PyString_AsString(tmp);
		strcpy(out_hash, buff);

		//ProfilerStop();
		return HSM_HMAC_OK;
	}
	else
		return HSM_HMAC_FAIL;
}

/*
 * assume that ersatz_pw is raw.
 * salt = HDF(pw) xor ersatz_pw
 * output: out_salt is base64 length 16
 */
int py_ersatz_salt(char *password, char *ersatz_pw, char *out_salt)
{
	/* HDF on password */
	char hmac_digest[HMAC_LEN];
	int ret = py_hsm_hmac(password, hmac_digest);
	
	if(ret != HSM_HMAC_OK)
		return ERSATZ_SALT_FAIL;

	/* todo: check len of ersatz pw*/

	/* pad ersatz pw with nulls */
	char ersatz_pw_padded[HMAC_LEN];
	memset(ersatz_pw_padded, 0, HMAC_LEN);
	strcpy(ersatz_pw_padded, ersatz_pw);
	
	/* xor the hmac_digest and padded ersatz  */
	char raw_salt[HMAC_LEN];
	int i;
	for(i = 0; i < HMAC_LEN; i++)
		raw_salt[i] = hmac_digest[i] ^ ersatz_pw_padded[i];
	/* encode base64, replace with '+' with '.' to maintain 
	   formating in passwd.master. Also, trim the salt down */
	b64_ntop((unsigned char*) raw_salt, RAW_SALT_LEN, out_salt, SALT_SIZE);
	for(i = 0; i < SALT_SIZE; i++)
		if(out_salt[i] == '+')
			out_salt[i] = '.';
	out_salt[SALT_SIZE] = '\0';
	return ERSATZ_SALT_OK;
}

int py_ersatz_hash(char *password, char *ersatz_salt, char *out_hash)
{
	/* todo: check the ersatz size */
	char hmac_digest[HMAC_LEN];
	int ret = py_hsm_hmac(password, hmac_digest);
	if(ret != HSM_HMAC_OK)
		return ERSATZ_HASH_FAIL;
	int i;
	char decoded_salt[SALT_SIZE ];
	/* convert back from . to + */
	for(i = 0; i < SALT_SIZE; i++)
		if(ersatz_salt[i] == '.')
			ersatz_salt[i] = '+';
	
	/* base64 decode ersatz salt   */
	b64_pton((unsigned char *) ersatz_salt, decoded_salt, SALT_SIZE);
	
	/* xor the hmac digest with the salt */
	for(i = 0; i < SALT_SIZE; i++)
		hmac_digest[i] = hmac_digest[i] ^ decoded_salt[i];
	
	for(i = 0; i < SALT_SIZE; i++)
		if(ersatz_salt[i] == '+')
			ersatz_salt[i] = '.';
	
	/* take a sha-512 hash */
	crypt_set_format("sha512");
	strcpy(out_hash, crypt(hmac_digest, ersatz_salt));
	return ERSATZ_HASH_OK;
}

int py_ersatz_pw_check(char *password, char *ersatz_payload)
{
	/* copy over the ersatz payload and detokenize to
	   get hash and salt values */
	assert(strlen(ersatz_payload) < ERSATZ_DIGEST_LEN);
	char ersatz_digest_tmp[ERSATZ_DIGEST_LEN];
	strcpy(ersatz_digest_tmp, ersatz_payload);
	strtok(ersatz_digest_tmp, "$");	//we don't need to store the hash type
	char *salt = strtok(NULL, "$");
	//char *hash = strtok(NULL, "$");

	/* calculate ersatz hash and compared with input */
	char hash_check[ERSATZ_DIGEST_LEN];
	py_ersatz_hash(password, salt, hash_check);
	#ifdef DBUG
	 printf("correct check\nhash_check=%s\nersatz_pl=%s\n", hash_check, ersatz_payload);
    #endif

	if(strcmp(hash_check, ersatz_payload) == 0)
		return ERSATZ_CORRECT_PW;
	else
	{
		/* check if input a ersatz pasword */
	  #ifdef DBUG
	    printf("ersatz check\nhash_check=%s\nersatz_pyl=%s\n", hash_check, crypt(password,salt));
      #endif
		strcpy(hash_check, crypt(password, salt));
		if(strcmp(hash_check, ersatz_payload) == 0)
			return ERSATZ_PW;
		else
			return ERSATZ_INCORRECT_PW;
	}
}

char * ersatz_word_generator(void)
{
	srand(time(NULL));
	int r = rand() % ERSATZ_WORDS_SIZE;
	if(RANDOM_ERSATZ_WORD == 1)
	{
		if(PRINT_GEN == 1)
			printf("Ersatz Password: " KGRN  "%s \n" RESET, ersatz_words[r]);
		return ersatz_words[r];
	}
	else
	{
		if(PRINT_GEN == 1)
			printf("Ersatz Password: " KGRN  "ersatz\n" RESET);
		return "ersatz";
	}
}
