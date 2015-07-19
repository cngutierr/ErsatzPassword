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

#include <security/pam_appl.h>
#include <security/pam_mod_misc.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

using namespace std;
int main(int argc, char *argv[])
{
	int num_times = 1;
	if(argc < 3)
	{
		printf("usage: %s <username> <password> [num time]\n", argv[0]);
		return 0;
	}
	if(argc > 3)
		num_times = atoi(argv[3]);

	pam_handle_t *pamh = NULL;  /** PAM data structure **/
	int retval;

	int i;
	timeval t1, t2;				/* hi-res timer www.songho.ca/misc/timer/timer.html */
	double elp_time, sum = 0.0;
	for(i = 0; i < num_times; i++)
	{
		/** Creating and initializing a PAM session **/
		gettimeofday(&t1, NULL);
		retval = pam_start("common-auth", argv[1], NULL, &pamh);
		pam_set_item(pamh, PAM_AUTHTOK, argv[2]);
		/* Authenticate user */
		if (retval == PAM_SUCCESS)
			retval = pam_authenticate(pamh, 0);
		/** Destroy the PAM session **/
		pam_end(pamh, retval);
		gettimeofday(&t2, NULL);
		elp_time = (t2.tv_sec - t1.tv_sec) * 1000.0;
		elp_time += (t2.tv_usec - t1.tv_usec) / 1000.0;
		sum += elp_time;
		printf("%f\n", elp_time);
		if (retval != PAM_SUCCESS)
			fprintf(stderr, "stderr: %s\n", pam_strerror(pamh, retval));
	//	sleep(1);
	}
	//printf("mean=%f\n", sum/num_times);
}

