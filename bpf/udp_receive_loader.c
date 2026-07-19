// SPDX-License-Identifier: MIT
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>

#define FENTRY_PROGRAM "udp_recv_fentry"
#define KPROBE_PROGRAM "udp_recv_kprobe"
#define DELIVERED_MAP "udp_delivered_counters"
#define RECEIVE_FUNCTION "udp_queue_rcv_skb"

struct loaded_state {
    struct bpf_object *object;
    struct bpf_link *link;
    __u32 map_id;
};

static volatile sig_atomic_t stopping;

static void stop_handler(int signum)
{
    (void)signum;
    stopping = 1;
}

static void destroy_state(struct loaded_state *state)
{
    if (state->link)
        bpf_link__destroy(state->link);
    if (state->object)
        bpf_object__close(state->object);
    memset(state, 0, sizeof(*state));
}

static int load_backend(const char *object_path, const char *backend,
                        struct loaded_state *state)
{
    const char *selected_name;
    struct bpf_program *selected = NULL;
    struct bpf_program *program;
    struct bpf_map *map;
    struct bpf_map_info info = {};
    __u32 info_len = sizeof(info);
    long link_error;
    int error;

    selected_name = strcmp(backend, "fentry") == 0
        ? FENTRY_PROGRAM : KPROBE_PROGRAM;
    state->object = bpf_object__open_file(object_path, NULL);
    error = libbpf_get_error(state->object);
    if (error) {
        state->object = NULL;
        fprintf(stderr, "%s open failed: %s\n", backend, strerror(-error));
        return error;
    }

    bpf_object__for_each_program(program, state->object) {
        bool enabled = strcmp(bpf_program__name(program), selected_name) == 0;

        bpf_program__set_autoload(program, enabled);
        if (enabled)
            selected = program;
    }
    if (!selected) {
        fprintf(stderr, "%s program %s not found\n", backend, selected_name);
        destroy_state(state);
        return -ENOENT;
    }

    error = bpf_object__load(state->object);
    if (error) {
        fprintf(stderr, "%s load failed: %s\n", backend, strerror(-error));
        destroy_state(state);
        return error;
    }

    if (strcmp(backend, "fentry") == 0)
        state->link = bpf_program__attach_trace(selected);
    else
        state->link = bpf_program__attach_kprobe(
            selected, false, RECEIVE_FUNCTION);
    link_error = libbpf_get_error(state->link);
    if (link_error) {
        state->link = NULL;
        fprintf(stderr, "%s attach failed: %s\n", backend,
                strerror((int)-link_error));
        destroy_state(state);
        return (int)link_error;
    }

    map = bpf_object__find_map_by_name(state->object, DELIVERED_MAP);
    if (!map) {
        fprintf(stderr, "map %s not found\n", DELIVERED_MAP);
        destroy_state(state);
        return -ENOENT;
    }
    error = bpf_obj_get_info_by_fd(bpf_map__fd(map), &info, &info_len);
    if (error) {
        error = -errno;
        fprintf(stderr, "map info failed: %s\n", strerror(errno));
        destroy_state(state);
        return error;
    }
    state->map_id = info.id;
    return 0;
}

static int valid_mode(const char *mode)
{
    return strcmp(mode, "auto") == 0 || strcmp(mode, "fentry") == 0 ||
           strcmp(mode, "kprobe") == 0;
}

int main(int argc, char **argv)
{
    struct loaded_state state = {};
    const char *object_path;
    const char *mode;
    const char *backend = NULL;
    int error;

    if (argc != 3) {
        fprintf(stderr, "usage: %s OBJECT {auto|fentry|kprobe}\n", argv[0]);
        return 2;
    }
    object_path = argv[1];
    mode = argv[2];
    if (!valid_mode(mode)) {
        fprintf(stderr, "invalid receive hook mode: %s\n", mode);
        return 2;
    }

    error = -EINVAL;
    if (strcmp(mode, "kprobe") != 0) {
        error = load_backend(object_path, "fentry", &state);
        if (!error)
            backend = "fentry";
    }
    if (!backend && strcmp(mode, "fentry") != 0) {
        if (strcmp(mode, "auto") == 0)
            fprintf(stderr, "fentry unavailable; trying kprobe fallback\n");
        error = load_backend(object_path, "kprobe", &state);
        if (!error)
            backend = "kprobe";
    }
    if (!backend) {
        fprintf(stderr, "receive-side attach failed for mode %s\n", mode);
        return error ? 1 : 0;
    }

    signal(SIGINT, stop_handler);
    signal(SIGTERM, stop_handler);
    printf("{\"backend\":\"%s\",\"map_id\":%u}\n", backend, state.map_id);
    fflush(stdout);

    while (!stopping)
        pause();

    destroy_state(&state);
    return 0;
}
