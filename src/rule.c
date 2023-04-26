#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <libgen.h>

#include <linux/bpf.h>

#include <bpf/bpf.h>


#define MIN(x, y)           ((x) < (y) ? (x) : (y))
#define ARRAY_COUNT(a)      (sizeof(a) / sizeof(a[0]))

#define PIN_IPV4_MAP        "/sys/fs/bpf/ipblock/ipv4_map"
#define PIN_IPV6_MAP        "/sys/fs/bpf/ipblock/ipv6_map"

#define log_err(...)        fprintf(stderr, __VA_ARGS__)


typedef enum {
    COMMAND_ADD = 0,
    COMMAND_DEL,
    COMMAND_LIST,
    COMMAND_UNUSED,
} command_e;


typedef struct {
    int                     af;
    int                     prefixlen;
    socklen_t               socklen;
    union {
        struct in_addr      addr;
        struct in6_addr     addr6;
    } sockaddr;
} cidr_t;


typedef struct {
    command_e               cmd;
    cidr_t                  cidr;
    enum xdp_action         action;
} options_t;


typedef struct {
    const char             *data;
    enum xdp_action         action;
} action_map_t;


typedef int (*command_call_pt)(options_t *);


static int do_add_cmd(options_t *opt);
static int do_del_cmd(options_t *opt);
static int do_list_cmd(options_t *opt);


// declare command function
static command_call_pt  commands[] = {
    do_add_cmd,
    do_del_cmd,
    do_list_cmd,
};


static action_map_t action_map[] = {
    { "allow", XDP_PASS },
    { "deny",  XDP_DROP },
};


static void
options_init(options_t *opt)
{
    memset(opt, 0, sizeof(*opt));

    opt->action = -1;
    opt->cmd = COMMAND_UNUSED;
}


static void
show_usage(const char *name)
{
    const char *program_doc_fmt =
        "Usage: %s cmd [rule]\n"
        "\n"
        "Commands:\n"
        "  -a cidr              Add IP rule use, with -p 'action'\n"
        "  -d cidr              Delete IP rule\n"
        "  -p action            Apply action. support allow|deny\n"
        "  -l                   List all IP rules\n"
        "  -h                   Print this help information\n"
        "\n"
        "Examples:\n"
        "  %s -a 192.168.1.0/24 -p allow\n"
        "  %s -d ::ffff:c612:13/128\n";

    printf(program_doc_fmt, name, name, name);
}


// IP addresses text format
//
// IPv4 ddd.ddd.ddd.ddd
// IPv6 x:x:x:x:x:x:x:x
//      x:x:x:x:x:x:d.d.d.d
static bool
is_ipv6_string(const char *s)
{
    return strchr(s, ':') != NULL;
}


static bool
is_valid_prefixlen(int af, int prefixlen)
{
    if (af == AF_INET) {
        return prefixlen > 0 && prefixlen <= 32;

    } else {
        return prefixlen > 0 && prefixlen <= 128;
    }
}


static int
parse_cidr(char *s, cidr_t *cidr, char **err)
{
    int              n, af, prefixlen;
    char            *p, addr[128];
    socklen_t        socklen;

    af = AF_INET;
    socklen = sizeof(struct in_addr);

    if (is_ipv6_string(s)) {
        af = AF_INET6;
        socklen = sizeof(struct in6_addr);
    }

    // IP address
    p = strchr(s, '/');
    if (p == NULL) {
        *err = "invalid CIDR format";
        return -1;
    }

    n = MIN(sizeof(addr), p - s);
    strncpy(addr, s, n);
    addr[n] = '\0';

    if (inet_pton(af, addr, &cidr->sockaddr) != 1) {
        *err = "invalid network address";
        return -1;
    }

    p += 1;

    // prefixlen
    prefixlen = atoi(p);

    if (!is_valid_prefixlen(af, prefixlen)) {
        *err = "invalid prefix length";
        return -1;
    }

    cidr->af = af;
    cidr->prefixlen = prefixlen;
    cidr->socklen = socklen;

    return 0;
}


static int
parse_action(char *s, enum xdp_action *action)
{
    int             i;

    for (i = 0; i < ARRAY_COUNT(action_map); i++) {
        if (strcmp(s, action_map[i].data) == 0) {
            *action = action_map[i].action;
            return 0;
        }
    }

    return -1;
}


static int
parse_cmdline(int argc, char *argv[], options_t *opt)
{
    int              c;
    char            *err;

    while ((c = getopt(argc, argv, "a:d:p:lh")) != -1) {
        switch (c) {
        case 'a':
            if (parse_cidr(optarg, &opt->cidr, &err) != 0) {
                log_err("ERR: failed parse CIDR '%s': %s\n", optarg, err);
                exit(EXIT_FAILURE);
            }

            opt->cmd = COMMAND_ADD;
            break;

        case 'd':
            if (parse_cidr(optarg, &opt->cidr, &err) != 0) {
                log_err("ERR: failed parse CIDR '%s': %s\n", optarg, err);
                exit(EXIT_FAILURE);
            }

            opt->cmd = COMMAND_DEL;
            break;

        case 'p':
            if (parse_action(optarg, &opt->action) != 0) {
                log_err("ERR: failed parse action '%s'\n", optarg);
                exit(EXIT_FAILURE);
            }
            break;

        case 'l':
            opt->cmd = COMMAND_LIST;
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
open_bpf_map(int af)
{
    int                      fd;
    const char              *path;

    assert(af == AF_INET || af == AF_INET6);

    if (af == AF_INET) {
        path = PIN_IPV4_MAP;
    } else {
        path = PIN_IPV6_MAP;
    }

    fd = bpf_obj_get(path);
    if (fd == -1) {
        return 1;
    }

    return fd;
}


static int
do_add_cmd(options_t *opt)
{
    int                          rc, fd;
    struct bpf_lpm_trie_key     *lpm;

    rc = 1;

    fd = open_bpf_map(opt->cidr.af);
    if (fd == -1) {
        log_err("Failed to open bpf map file, err(%d):%s\n",
                errno, strerror(errno));
        return rc;
    }

    lpm = malloc(sizeof(*lpm) + opt->cidr.socklen);
    if (lpm == NULL) {
        log_err("Failed to malloc, err(%d):%s\n", errno, strerror(errno));

        close(fd);
        return rc;
    }

    lpm->prefixlen = opt->cidr.prefixlen;
    memcpy(lpm->data, &opt->cidr.sockaddr, opt->cidr.socklen);

    if (bpf_map_update_elem(fd, lpm, &opt->action, BPF_ANY) != 0) {
        log_err("Failed to update bpf map item err(%d):%s\n",
                errno, strerror(errno));
        goto fail;
    }

    rc = 0;

fail:

    free(lpm);
    close(fd);

    return rc;
}


static int
do_del_cmd(options_t *opt)
{
    int                          rc, fd;
    struct bpf_lpm_trie_key     *lpm;

    rc = 1;

    fd = open_bpf_map(opt->cidr.af);
    if (fd == -1) {
        log_err("Failed to open bpf map file, err(%d):%s\n",
                errno, strerror(errno));
        return rc;
    }

    lpm = malloc(sizeof(*lpm) + opt->cidr.socklen);
    if (lpm == NULL) {
        log_err("Failed to malloc, err(%d):%s\n", errno, strerror(errno));

        close(fd);
        return rc;
    }

    lpm->prefixlen = opt->cidr.prefixlen;
    memcpy(lpm->data, &opt->cidr.sockaddr, opt->cidr.socklen);

    if (bpf_map_delete_elem(fd, lpm) != 0) {
        log_err("Failed to delete bpf map item err(%d):%s\n",
                errno, strerror(errno));
        goto fail;
    }

    rc = 0;

fail:

    free(lpm);
    close(fd);

    return rc;
}


static const char *
action_str(enum xdp_action action)
{
    switch (action) {
    case XDP_PASS:
        return "allow";

    case XDP_DROP:
        return "deny";

    default:
        return "unknown";
    }
}


static int
dump_rules(int af)
{
    struct bpf_lpm_trie_key     *key;
    enum xdp_action              action;
    char                         buf[INET6_ADDRSTRLEN];
    const char                  *p;
    int                          rc, map_fd;

    key = NULL;
    rc = map_fd = -1;

    key = calloc(1, sizeof(*key) + sizeof(struct in6_addr));
    if (key == NULL) {
        log_err("Failed to calloc, err(%d):%s\n", errno, strerror(errno));
        goto fail;
    }

    map_fd = open_bpf_map(af);
    if (map_fd == -1) {
        log_err("Failed to open bpf map file, err(%d):%s\n",
                errno, strerror(errno));

        goto fail;
    }

    while (bpf_map_get_next_key(map_fd, key, key) == 0) {
        if (bpf_map_lookup_elem(map_fd, key, &action)) {
            if (errno == ENOENT) {
                continue;
            }

            log_err("map lookup error: %s\n", strerror(errno));
            goto fail;
        }

        p = inet_ntop(af, key->data, buf, INET6_ADDRSTRLEN);
        if (p == NULL) {
            log_err("inet_ntop error: %s\n", strerror(errno));
            goto fail;
        }

        printf(" %s/%d -> %s\n", p, key->prefixlen, action_str(action));
    }

    rc = 0;

fail:
    if (map_fd != -1) {
        close(map_fd);
    }

    if (key != NULL) {
        free(key);
    }

    return rc;
}


static int
do_list_cmd(options_t *opt)
{
    printf("IPv4 Rule List:\n");
    if (dump_rules(AF_INET) != 0) {
        return -1;
    }

    printf("\n");

    printf("IPv6 Rule List:\n");
    if (dump_rules(AF_INET6) != 0) {
        return -1;
    }

    printf("\n");

    return 0;
}


int
main(int argc, char *argv[])
{
    options_t               opt;

    options_init(&opt);

    if (parse_cmdline(argc, argv, &opt) != 0) {
        show_usage(basename(argv[0]));
        return 1;
    }

    if (opt.cmd == COMMAND_UNUSED) {
        log_err("ERR: required command missing.\n\n");
        show_usage(basename(argv[0]));
        return 1;
    }

    if (opt.cmd == COMMAND_ADD && opt.action == -1) {
        log_err("ERR: required option -p 'action' missing.\n\n");
        show_usage(basename(argv[0]));
        return 1;
    }

    assert(opt.cmd >= 0 && opt.cmd < COMMAND_UNUSED);

    return commands[opt.cmd](&opt);
}
