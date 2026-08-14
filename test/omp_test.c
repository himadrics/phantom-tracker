// SPDX-License-Identifier: GPL-2.0-or-later
/*
  OpenMP Test Program for Guest VM
  Spawns OpenMP threads that continuously execute work until Ctrl+C (SIGINT) is received.
  Compile with: gcc -fopenmp -O2 omp_test.c -o omp_test
*/

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <omp.h>

static volatile int keep_running = 1;

static void handle_sigint(int sig)
{
	(void)sig;
	printf("\n[omp_test] Caught signal (Ctrl+C), stopping OpenMP threads...\n");
	keep_running = 0;
}

int main(int argc, char *argv[])
{
	int num_threads = 0;

	signal(SIGINT, handle_sigint);
	signal(SIGTERM, handle_sigint);

	#pragma omp parallel
	{
		#pragma omp single
		{
			num_threads = omp_get_num_threads();
			printf("[omp_test] Started OpenMP parallel region with %d threads (PID: %d)\n",
			       num_threads, getpid());
			printf("[omp_test] Press Ctrl+C to stop.\n");
		}
	}

	#pragma omp parallel
	{
		int tid = omp_get_thread_num();
		unsigned long long iterations = 0;

		printf("[omp_test] Thread %d initialized and running...\n", tid);

		while (keep_running) {
			// Perform dummy CPU work
			volatile unsigned long long dummy = 0;
			for (int i = 0; i < 1000000; i++) {
				dummy += i;
			}
			iterations++;

			// Periodically yield slightly to prevent hard CPU lockup if on single vCPU
			if (iterations % 500 == 0) {
				usleep(1000);
			}
		}

		printf("[omp_test] Thread %d finished (completed %llu work blocks).\n", tid, iterations);
	}

	printf("[omp_test] All OpenMP threads exited cleanly.\n");
	return 0;
}
