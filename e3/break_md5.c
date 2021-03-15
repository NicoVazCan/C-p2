#include <sys/types.h>
#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>

#define PASS_LEN 6
#define NTHREADS 6
#define PROG_LEN 10
#define PROG_FRE 10000

struct args
{	long start, end;
	int nMd5;
	float prop;
	char **md5;
	pthread_mutex_t *lokIn;
};

struct thread_info
{
	pthread_t id;
	struct args args;
};

int isEmptyArray(char *array[])
{	return(array[0] == NULL); }

int hasNextArray(char *array[], int n, int tam)
{	return(n < tam && array[n] != NULL); }

void copyStringArray(char *dest[], char *source[], int tam)
{	int i = 0, j = 0, rep = 0;

	for(; i < tam; i++) 
	{	for (int k = i-1; k >= 0 && !rep; k--)
		{	rep = strcmp(dest[k], source[i]) == 0;}

		if(!rep) 
		{	dest[j] = source[i];
			j++;
		}
	}
	for (; j < tam; j++) { dest[j] = NULL;}
}

void removeStringArray(char *array[], int n, int tam)
{	for(int i = n; i < tam-1; i++) { array[i] = array[i+1]; }

	if(array[tam-1] != NULL) { array[tam-1] = NULL; }
}


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

	for(long i = args->start; i < args->end && !isEmptyArray(args->md5); i++) 
	{	long_to_pass(i, pass);

		MD5(pass, PASS_LEN, res);

		to_hex(res, hex_res);

		args->prop = ((double) i)/((double) args->end);

		for (int k = 0; hasNextArray(args->md5, k, args->nMd5); k++)
		{	if(!strcmp(hex_res, args->md5[k]))
			{	pthread_mutex_lock(args->lokIn);

				printf("\33[2K\r%s: %s\n", args->md5[k], pass);

				pthread_mutex_unlock(args->lokIn);
				removeStringArray(args->md5, k, args->nMd5);
			}
		}
	}

	return NULL;
}

void print_break_pass_with_threads(char *md5[], int nMd5)
{	long bound = ipow(26, PASS_LEN);
	long rest = bound%NTHREADS;
	char *cpMd5[nMd5];
	struct thread_info threads[NTHREADS];
	int i;
	float avg, total;
	char progBar[PROG_LEN+1];
	pthread_mutex_t lokIn;
	bound /= NTHREADS;
	progBar[0] = '[';
	progBar[PROG_LEN] = ']';
	copyStringArray(cpMd5, md5, nMd5);
	pthread_mutex_init(&lokIn, NULL);
	

	for (i = 0; i < NTHREADS; i++)
	{	threads[i].args.start = bound*i;
		threads[i].args.end   = bound*(i+1) + (i == NTHREADS-1? rest: 0);
		threads[i].args.prop  = 0;
		threads[i].args.md5   = cpMd5;
		threads[i].args.nMd5  = nMd5;
		threads[i].args.lokIn = &lokIn;

		if(pthread_create(&threads[i].id, NULL, 
		                  break_pass, &threads[i].args) == -1)
		{	printf("Could not create thread #%d", i);
			exit(1);
		}
	}

	while(!isEmptyArray(cpMd5) && avg < 1)
	{	
		if(pthread_mutex_trylock(&lokIn) == EBUSY && cpMd5[1] == NULL)
		{	break; }

		printf("\rProgress at ");
		total = 0;
		for (i = 0; i < NTHREADS; i++)
		{	if(i < 10) { printf("%d: %.2f%%, ", i, threads[i].args.prop); }
			total += threads[i].args.prop;
		}
		avg = total/NTHREADS;

		for(i = 1; i < (int) PROG_LEN*avg; i++) { progBar[i] = '#'; }
		for(; i < PROG_LEN; i++) { progBar[i] = '-'; }

		printf("total: %.2f%% %s", avg*100, progBar);

		pthread_mutex_unlock(&lokIn);
		usleep(PROG_FRE);
	}

	for(i = 0; i < NTHREADS; i++)
	{	pthread_join(threads[i].id, NULL); }
}

int main(int argc, char *argv[]) 
{	if(argc < 2) 
	{	printf("Use: %s string, ...\n", argv[0]);
		exit(0);
	}

	print_break_pass_with_threads(&argv[1], argc-1);
	
	return 0;
}
