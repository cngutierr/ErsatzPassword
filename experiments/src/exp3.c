#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include "ersatz.h"

//compile with g++48 -lpam -o exp1 exp1.cpp
int main(int argc, char *argv[]) 
{
	if(argc < 2)
	{
		printf("Experiment 3 - Ersatz Hashes\n");
		printf("usage: %s <password>\n", argv[0]);
		return 0; 
	}
	char salt[33];
	char *ersatz_pw; 
	char final_hash[ERSATZ_DIGEST_LEN];
	py_ersatz_init();
	ersatz_pw = ersatz_word_generator();
	py_ersatz_salt(argv[1], ersatz_pw, salt);
	py_ersatz_hash(argv[1], salt, final_hash);
	printf("user%d:%s %s\n", atoi(argv[2]), final_hash, ersatz_pw);
	py_ersatz_close();
}
