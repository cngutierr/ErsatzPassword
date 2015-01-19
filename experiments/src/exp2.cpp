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

