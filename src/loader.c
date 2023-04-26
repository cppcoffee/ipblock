#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>

#include <getopt.h>
#include <libgen.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <net/if.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/in.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "ipblock.skel.h"


#define BUF_SIZE            4096
#define PIN_DIR             "/sys/fs/bpf/ipblock"

#define log_err(...)        fprintf(stderr, __VA_ARGS__)


struct options {
    const char *ifname;
    int         ifindex;
    bool        debug;
    bool        do_unload;
    uint32_t    xdp_flags;
};


static struct options       opt;


static void
options_init(struct options *opt)
{
    memset(opt, 0, sizeof(*opt));

    opt->xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
    opt->ifindex = -1;
}


static int
libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG && !opt.debug) {
        return 0;
    }

    fprintf(stderr, "[%d] ", level);
    return vfprintf(stderr, fmt, args);
}


static void
rlimit_bump_memlock(void)
{
    struct rlimit rlim_new = {
        .rlim_cur	= RLIM_INFINITY,
        .rlim_max	= RLIM_INFINITY,
	};

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new) != 0) {
        log_err("Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }
}


static void
show_usage(const char *prog_name)
{
    const char program_doc_fmt[] =
        "Usage: %s (options)\n"
        "\n"
        "Options:\n"
        "  -d dev               Operate on device <ifname>\n"
        "  -u                   Unload XDP program instead of loading\n"
        "  -A                   Auto mode. default mode\n"
        "  -S                   Skb mode\n"
        "  -N                   Native mode\n"
        "  -O                   Offload mode\n"
        "  -F                   Force install, replacing existing program on interface\n"
        "  -D                   Debug output\n"
        "  -h                   Print this help information\n";

    printf(program_doc_fmt, prog_name);
}


static int
parse_cmdline(int argc, char *argv[], struct options *opt)
{
    int             c;

    while ((c = getopt(argc, argv, "d:uASNOFDh")) != -1) {
        switch (c) {
        case 'd':
            opt->ifindex = if_nametoindex(optarg);
            if (opt->ifindex == 0) {
                log_err("ERR: -d name unknown err(%d):%s\n",
                        errno, strerror(errno));
                return -1;
            }

            opt->ifname = strdup(optarg);
            break;

        case 'u':
            opt->do_unload = true;
            break;

        case 'A':
            opt->xdp_flags &= ~XDP_FLAGS_MODES;
            break;

        case 'S':
            opt->xdp_flags &= ~XDP_FLAGS_MODES;
            opt->xdp_flags |= XDP_FLAGS_SKB_MODE;
            break;

        case 'N':
            opt->xdp_flags &= ~XDP_FLAGS_MODES;
            opt->xdp_flags |= XDP_FLAGS_DRV_MODE;
            break;

        case 'O':
            opt->xdp_flags &= ~XDP_FLAGS_MODES;
            opt->xdp_flags |= XDP_FLAGS_HW_MODE;
            break;

        case 'F':
            opt->xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
            break;

        case 'D':
            opt->debug = true;
            break;

        case 'h':
            show_usage(basename(argv[0]));
            exit(EXIT_SUCCESS);
            break;

        default:
            return -1;
        }
    }

    if (optind < argc) {
        log_err("non-option ARGV-elements: ");
        while (optind < argc) {
            log_err("%s ", argv[optind++]);
        }
        log_err("\n");
    }

    return 0;
}


static int
xdp_link_attach(int ifindex, uint32_t xdp_flags, int prog_fd)
{
    int             err;
    uint32_t        old_flags;

    err = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL);
    if (err == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)) {
        old_flags = xdp_flags;

        xdp_flags &= ~XDP_FLAGS_MODES;

        if (old_flags & XDP_FLAGS_SKB_MODE) {
            xdp_flags |= XDP_FLAGS_DRV_MODE;

        } else {
            xdp_flags |= XDP_FLAGS_SKB_MODE;
        }

        err = bpf_xdp_attach(ifindex, -1, xdp_flags, NULL);
        if (!err) {
            err = bpf_xdp_attach(ifindex, prog_fd, old_flags, NULL);
        }
    }

    if (err < 0) {
        log_err("ERR: ifindex(%d) link set xdp fd failed (%d): %s\n",
                ifindex, -err, strerror(-err));

        switch (-err) {
        case EBUSY:
        case EEXIST:
            log_err("Hint: XDP already loaded on device use --force to swap/replace\n");
            break;

        case EOPNOTSUPP:
            log_err("Hint: Native-XDP not supported use -S(skb-mode) or -A(auto-mode)\n");
            break;

        default:
            break;
        }

        return 1;
    }

    return 0;
}


static int
xdp_link_detach(int ifindex, uint32_t xdp_flags, uint32_t expected_prog_id)
{
    int                 err;
    uint32_t            curr_prog_id;

    err = bpf_xdp_query_id(ifindex, xdp_flags, &curr_prog_id);
    if (err) {
        log_err("ERR: get link xdp id failed (err=%d): %s\n",
                -err, strerror(-err));
        return 1;
    }

    if (curr_prog_id == 0) {
        return 0;
    }

    if (expected_prog_id && curr_prog_id != expected_prog_id) {
        log_err("ERR: expected prog ID(%d) no match(%d), not removing\n",
                expected_prog_id, curr_prog_id);
        return 1;
    }

    err = bpf_xdp_attach(ifindex, -1, xdp_flags, NULL);
    if (err < 0) {
        log_err("ERR: link set xdp failed (err=%d): %s\n",
                -err, strerror(-err));
        return 1;
    }

    printf("INFO: removed XDP prog ID:%d on ifindex:%d\n",
           curr_prog_id, ifindex);

    return 0;
}


static int
unpin_maps_in_bpf_object(struct ipblock_bpf *skel)
{
    int                 err, len;
    char                filename[PATH_MAX];

    len = snprintf(filename, sizeof(filename), "%s/%s",
                   PIN_DIR, bpf_map__name(skel->maps.ipv4_map));
    filename[len] = '\0';

    if (access(filename, F_OK) != 0) {
        rmdir(PIN_DIR);
        return 0;
    }

    err = bpf_object__unpin_maps(skel->obj, PIN_DIR);
    if (err != 0) {
        return err;
    }

    err = rmdir(PIN_DIR);
    if (err != 0) {
        return -errno;
    }

    return 0;
}


static int
pin_maps_in_bpf_object(struct ipblock_bpf *skel)
{
    int             err;

    err = unpin_maps_in_bpf_object(skel);
    if (err != 0) {
        log_err("ERR: Unpinning maps in %s failed (err=%d): %s\n",
                PIN_DIR, -err, strerror(-err));
        return err;
    }

    err = bpf_object__pin_maps(skel->obj, PIN_DIR);
    if (err != 0) {
        log_err("ERR: Pinning maps in %s failed (err=%d): %s\n",
                PIN_DIR, -err, strerror(-err));
        return err;
    }

    return 0;
}


// load xdp prog
static int
do_load(struct options *opt, struct ipblock_bpf *skel)
{
    int             err;

    err = xdp_link_attach(opt->ifindex, opt->xdp_flags,
                          bpf_program__fd(skel->progs.xdp_prog));
    if (err != 0) {
        return err;
    }

    err = pin_maps_in_bpf_object(skel);
    if (err != 0) {
        return err;
    }

    printf("Success: XDP prog attached on device:%s(ifindex:%d)\n",
           opt->ifname, opt->ifindex);

    return 0;
}


// unload xdp
static int
do_unload(struct options *opt, struct ipblock_bpf *skel)
{
    int             err;

    err = xdp_link_detach(opt->ifindex, opt->xdp_flags, 0);
    if (err != 0) {
        log_err("ERR: detach ifname(%s) xdp prog failed (err=%d): %s\n",
                opt->ifname, -err, strerror(-err));
        return err;
    }

    err = unpin_maps_in_bpf_object(skel);
    if (err != 0) {
        log_err("ERR: unpin maps failed pin_dir(%s) (err=%d): %s\n",
                PIN_DIR, -err, strerror(-err));
        return err;
    }

    return 0;
}


int
main(int argc, char *argv[])
{
    int                          err;
    struct options               opt;
    struct ipblock_bpf          *skel;

    options_init(&opt);

    if (parse_cmdline(argc, argv, &opt) == -1) {
        show_usage(basename(argv[0]));
        return 1;
    }

    if (opt.ifindex == -1) {
        log_err("ERR: required option -d missing\n\n");
        show_usage(basename(argv[0]));
        return 1;
    }

    rlimit_bump_memlock();

    // Set up libbpf errors and debug info callback
    libbpf_set_print(libbpf_print_fn);

    skel = ipblock_bpf__open_and_load();
    if (skel == NULL) {
        log_err("Failed to load and verify BPF skeleton, %s\n",
                strerror(errno));
        return 1;
    }

    if (opt.do_unload) {
        err = do_unload(&opt, skel);
    } else {
        err = do_load(&opt, skel);
    }

    ipblock_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
