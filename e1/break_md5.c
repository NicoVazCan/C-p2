#include <sys/types.h>
#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define PASS_LEN 6
#define NTHREADS 4

struct args
{	long start, end;
	int *done;
	char *pass, *md5;
};

struct thread_info
{
	pthread_t id;
	struct args args;
};

long ipow(long base, int exp)
{
    long res = 1;
    for (;;)
    {
        if (exp & 1)
            res *= base;
        exp >>= 1;
        if (!exp)
            break;
        base *= base;
    }

    return res;
}

long pass_to_long(char *str) {
    long res = 0;

    for(int i=0; i < PASS_LEN; i++)
        res = res * 26 + str[i]-'a';

    return res;
};

void long_to_pass(long n, unsigned char *str) {  // str should have size PASS_SIZE+1
    for(int i=PASS_LEN-1; i >= 0; i--) {
        str[i] = n % 26 + 'a';
        n /= 26;
    }
    str[PASS_LEN] = '\0';
}

void to_hex(unsigned char *res, char *hex_res) {
    for(int i=0; i < MD5_DIGEST_LENGTH; i++) {
        snprintf(&hex_res[i*2], 3, "%.2hhx", res[i]);
    }
    hex_res[MD5_DIGEST_LENGTH * 2] = '\0';
}

void *break_pass(void *aux)
{	struct args *args = (struct args*) aux;
	unsigned char res[MD5_DIGEST_LENGTH];
	char hex_res[MD5_DIGEST_LENGTH * 2 + 1];
	unsigned char pass[PASS_LEN + 1];

	for(long i = args->start; i < args->end && !*args->done; i++) 
	{	long_to_pass(i, pass);

		MD5(pass, PASS_LEN, res);

		to_hex(res, hex_res);

		if(!strcmp(hex_res, args->md5))
		{	*args->done = 1;
			return strcpy(args->pass, (char*) pass);
		}
	}

	return NULL;
}

void break_pass_with_threads(char *pass, char *md5)
{	long bound = ipow(26, PASS_LEN);
	long rest = bound%NTHREADS;
	struct thread_info threads[NTHREADS];
	int done = 0, i;
	bound /= NTHREADS;

	for (i = 0; i < NTHREADS; i++)
	{	threads[i].args.start = bound*i;
		threads[i].args.end   = bound*(i+1) + (i == NTHREADS-1? rest: 0);
		threads[i].args.done  = &done;
		threads[i].args.pass  = pass;
		threads[i].args.md5   = md5;

		if(pthread_create(&threads[i].id, NULL, 
		                  break_pass, &threads[i].args) == -1)
		{	printf("Could not create thread #%d", i);
			exit(1);
		}
	}

	for(i = 0; i < NTHREADS; i++)
	{	pthread_join(threads[i].id, NULL); }
}

int main(int argc, char *argv[]) 
{	char pass[PASS_LEN + 1];
	if(argc < 2) 
	{	printf("Use: %s string\n", argv[0]);
		exit(0);
	}
	break_pass_with_threads(pass, argv[1]);

	printf("%s: %s\n", argv[1], pass);
	return 0;
}
