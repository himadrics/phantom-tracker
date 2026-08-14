// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "linkedlist.h"
#include "register_vm.h"

#define QMP_VCPU_SIZE 4096

#define QMP_CONNECT_RETRY_S 1

/*
 * Inputs: data - pointer to qmp_vpcu struct
 * Outputs: None
 * Description: Prints the CPU index and thread ID for a given vCPU node
 */
static void print_vcpu(void *data)
{
	struct qmp_vpcu *v = (struct qmp_vpcu *)data;

	if (!v)
		return;

	printf("\ncpu=%d thread=%d\n", v->cpuIndex, v->threadId);
}

/*
 * Inputs: query_result - JSON response string from QMP query-cpus-fast
 * Outputs: Returns a linked list of qmp_vpcu structs or NULL on failure
 * Description: Parses a QMP query-cpus-fast JSON response to extract thread-id and cpu-index into a linked list
 */
static Node *extract_vcpu_info(const char *query_result)
{
	const char *entry_key = "{\"thread-id\": ";
	const char *cpu_key = "\"cpu-index\": ";
	const char *str = query_result;
	Node *head;

	head = create_node(NULL);
	if (!head) {
		fprintf(stderr,
			"extract_vcpu_info: failed to create list head\n");
		return NULL;
	}

	while ((str = strstr(str, entry_key)) != NULL) {
		struct qmp_vpcu *vcpu;
		const char *cpu_ptr;
		int thread_id = -1;
		int cpu_index = -1;

		str += strlen(entry_key);
		sscanf(str, "%d", &thread_id);

		cpu_ptr = strstr(str, cpu_key);
		if (cpu_ptr) {
			cpu_ptr += strlen(cpu_key);
			sscanf(cpu_ptr, "%d", &cpu_index);
		}

		vcpu = malloc(sizeof(*vcpu));
		if (!vcpu) {
			fprintf(stderr, "extract_vcpu_info: malloc failed\n");
			/*
			 * Return what we have so far rather than leaking
			 * the already-built list.
			 */
			return head;
		}

		vcpu->threadId = thread_id;
		vcpu->cpuIndex = cpu_index;

		push_back(&head, vcpu);

		printf("Thread ID: %d\n", thread_id);
		printf("CPU Index: %d\n\n", cpu_index);
	}

	print_nodes(head, print_vcpu);

	return head;
}

/*
 * Inputs: path - path to the UNIX domain socket
 * Outputs: Returns a valid file descriptor on success, -1 on error
 * Description: Creates and connects a UNIX socket to the specified path, retrying until the peer is ready
 */
static int qmp_connect(const char *path)
{
	struct sockaddr_un addr;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	if (strlen(path) >= sizeof(addr.sun_path)) {
		fprintf(stderr, "qmp_connect: socket path too long\n");
		close(fd);
		return -1;
	}

	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	printf("Connecting to socket");
	while (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		printf(".");
		fflush(stdout);
		sleep(QMP_CONNECT_RETRY_S);
	}
	printf("\nConnected to socket\n");

	return fd;
}

/*
 * Inputs: fd - file descriptor for the UNIX socket
 *         buf - buffer to store the response
 *         bufsz - size of the response buffer
 * Outputs: Returns the number of characters read, or -1 on error
 * Description: Reads characters from the socket until a newline is reached
 */
static ssize_t qmp_read_line(int fd, char *buf, size_t bufsz)
{
	size_t total = 0;
	while (total < bufsz - 1) {
		char c;
		ssize_t n = read(fd, &c, 1);
		if (n < 0) {
			perror("read");
			return -1;
		}
		if (n == 0) {
			break;
		}
		buf[total++] = c;
		if (c == '\n') {
			break;
		}
	}
	buf[total] = '\0';
	return total;
}

/*
 * Inputs: fd - file descriptor for the UNIX socket
 *         cmd - QMP command string to send
 *         buf - buffer to store the response
 *         bufsz - size of the response buffer
 * Outputs: Returns 0 on success, -1 if the write or read failed
 * Description: Writes a QMP command to the socket and reads the corresponding response into the provided buffer
 */
static int qmp_send_recv(int fd, const char *cmd, char *buf, size_t bufsz)
{
	ssize_t n;

	n = write(fd, cmd, strlen(cmd));
	if (n < 0) {
		perror("write");
		return -1;
	}

	if (qmp_read_line(fd, buf, bufsz) < 0) {
		return -1;
	}

	return 0;
}

/*
 * Inputs: argc - number of command line arguments
 *         argv - array of command line arguments
 * Outputs: Returns 0 on success, 1 on failure
 * Description: Main function to connect to a VM's QMP socket, extract vCPU info, register the VM, and setup its maps
 */
int main(int argc, char *argv[])
{
	const char *qmp_capabilities = "{ \"execute\": \"qmp_capabilities\" }";
	const char *query_cpus = "{ \"execute\": \"query-cpus-fast\" }";
	char *buff = NULL;
	const char *unix_socket;
	const char *vm_name;
	int nb_vcpus;
	size_t bufsz;
	Node *vcpus;
	int sockfd;
	int ret = 1;

	if (argc < 4) {
		fprintf(stderr, "Usage: %s <socket_path> <vm_name> <nb_vcpus>\n", argv[0]);
		return 1;
	}

	unix_socket = argv[1];
	vm_name = argv[2];
	nb_vcpus = atoi(argv[3]);

	bufsz = (size_t)nb_vcpus * QMP_VCPU_SIZE;
	buff = malloc(bufsz);
	if (buff == NULL) {
		perror("Error allocating QMP Buffer");
		return 1;
	}

	sockfd = qmp_connect(unix_socket);
	if (sockfd < 0)
		goto cleanup_buff;

	/* 1. Read QMP greeting */
	memset(buff, 0, bufsz);
	if (qmp_read_line(sockfd, buff, bufsz) < 0) {
		perror("read greeting");
		goto cleanup_fd;
	}
	printf("QMP greeting: %s\n", buff);

	/* 2. Capability negotiation */
	if (qmp_send_recv(sockfd, qmp_capabilities, buff, bufsz) < 0)
		goto cleanup_fd;
	printf("Handshake response: %s\n", buff);

	/* 3. Query vCPU info */
	if (qmp_send_recv(sockfd, query_cpus, buff, bufsz) < 0)
		goto cleanup_fd;
	printf("VM status: %s\n", buff);

	vcpus = extract_vcpu_info(buff);
	if (!vcpus) {
		fprintf(stderr, "failed to extract vcpu info\n");
		goto cleanup_fd;
	}

	if (register_vm(vcpus, vm_name, unix_socket, nb_vcpus) < 0) {
		fprintf(stderr, "register_vm failed\n");
		goto cleanup_fd;
	}

	if (setup_vm_maps(vm_name) < 0) {
		fprintf(stderr, "setup_vm_maps failed\n");
		goto cleanup_fd;
	}

	ret = 0;

cleanup_fd:
	close(sockfd);
cleanup_buff:
	free(buff);
	return ret;
}