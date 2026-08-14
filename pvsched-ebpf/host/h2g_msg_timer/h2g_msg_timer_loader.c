/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Contributors:
 *   Human: Himadri Chhaya-Shailesh
 *   AI: ChatGPT-5.5
 */

#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>

static volatile sig_atomic_t exiting;

static void handle_signal(int sig)
{
  (void) sig;
	exiting = 1;
}

int main (void)
{
  const char *obj_path = "h2g_msg_timer.bpf.o";
  struct bpf_object *obj = NULL;
  struct bpf_link *link = NULL;
  struct bpf_program *prog;
  int timer_map_fd;
  int err;

  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);

  obj = bpf_object__open_file(obj_path, NULL);
  err = libbpf_get_error(obj);

  if (err) {
    fprintf(stderr, "failed to open BPF object file %s: %s\n", obj_path, strerror(-err));
    return 1;
  }

  err = bpf_object__load(obj);

  if (err) {
    fprintf(stderr, "failed to load BPF object %s: %s\n", obj_path, strerror(-err));
    goto cleanup;
  }

  timer_map_fd = bpf_object__find_map_fd_by_name(obj, "h2g_msg_timer_map");

  if (timer_map_fd < 0) {
    fprintf(stderr, "failed to find h2g_msg_timer_map in BPF object %s\n", obj_path);
    goto cleanup;
  }

  prog = bpf_object__find_program_by_name(obj, "h2g_msg_timer_init");

  if (!prog) {
    fprintf(stderr, "failed to find BPF program h2g_msg_timer_init in BPF object %s\n", obj_path);
    goto cleanup;
  }

  link = bpf_program__attach(prog);
  err = libbpf_get_error(link);

  if (err) {
    link = NULL;
    fprintf(stderr, "failed to attach BPF program h2g_msg_timer_init: %s\n", strerror(-err));
    goto cleanup;
  }

  printf("Info: Loaded BPF program %s\n", bpf_program__name(prog));
  printf("Info: hg_timer_map_fd=%d\n", timer_map_fd);
  printf("Info: Press Ctrl+C to exit\n");

  while (!exiting)
	  pause();

cleanup:
	bpf_link__destroy(link);
	bpf_object__close(obj);

	return err ? 1 : 0;
}