// SPDX-License-Identifier: MIT
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define TCP_CHANNEL_MAP "tcp_channel_flows"

struct loaded_state {
    struct bpf_object *object;
    struct bpf_link **links;
    size_t link_count;
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
    if (state->links) {
        for (size_t index = 0; index < state->link_count; index++) {
            if (state->links[index])
                bpf_link__destroy(state->links[index]);
        }
        free(state->links);
    }
    if (state->object)
        bpf_object__close(state->object);
    memset(state, 0, sizeof(*state));
}

static int append_link(struct loaded_state *state, struct bpf_link *link)
{
    struct bpf_link **links;
    size_t next = state->link_count + 1;

    links = realloc(state->links, next * sizeof(*links));
    if (!links)
        return -ENOMEM;
    state->links = links;
    state->links[state->link_count] = link;
    state->link_count = next;
    return 0;
}

static int load_tcp_channel(const char *object_path, struct loaded_state *state)
{
    struct bpf_program *program;
    struct bpf_map *map;
    struct bpf_map_info info = {};
    __u32 info_len = sizeof(info);
    int error;

    state->object = bpf_object__open_file(object_path, NULL);
    error = libbpf_get_error(state->object);
    if (error) {
        state->object = NULL;
        fprintf(stderr, "open failed: %s\n", strerror(-error));
        return error;
    }

    error = bpf_object__load(state->object);
    if (error) {
        fprintf(stderr, "load failed: %s\n", strerror(-error));
        destroy_state(state);
        return error;
    }

    bpf_object__for_each_program(program, state->object) {
        struct bpf_link *link = bpf_program__attach_trace(program);
        long link_error = libbpf_get_error(link);

        if (link_error) {
            fprintf(stderr, "attach %s failed: %s\n",
                    bpf_program__name(program), strerror((int)-link_error));
            destroy_state(state);
            return (int)link_error;
        }
        error = append_link(state, link);
        if (error) {
            bpf_link__destroy(link);
            destroy_state(state);
            return error;
        }
    }

    map = bpf_object__find_map_by_name(state->object, TCP_CHANNEL_MAP);
    if (!map) {
        fprintf(stderr, "map %s not found\n", TCP_CHANNEL_MAP);
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

int main(int argc, char **argv)
{
    struct loaded_state state = {};
    const char *object_path;
    int error;

    if (argc != 2) {
        fprintf(stderr, "usage: %s OBJECT\n", argv[0]);
        return 2;
    }
    object_path = argv[1];

    error = load_tcp_channel(object_path, &state);
    if (error)
        return 1;

    signal(SIGINT, stop_handler);
    signal(SIGTERM, stop_handler);
    printf("{\"map_id\":%u}\n", state.map_id);
    fflush(stdout);

    while (!stopping)
        pause();

    destroy_state(&state);
    return 0;
}
