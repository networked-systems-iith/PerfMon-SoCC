/*
    Xflow_ringbuf_test_user : User-space program to load and consume the flow record entries of the ring-buffer
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <math.h>
#include <locale.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <signal.h>
#include <stdint.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
// code for mongo
// #include <bson/bson.h>
// #include <mongoc/mongoc.h>
//
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <linux/bpf.h>

#include "../common/common_user_bpf_xdp.h"
#include "../common/common_params.h"
#include "../common/xdp_stats_kern_user.h"
#include "../common/common_defines.h"
#include "../common/common_utils.h"
#include "../common/hashmap.h"

#include <pthread.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 512
#define MAX_ELEMENTS_PER_PACKET 400
#define TC_HOOK_EXISTS
static volatile bool exiting = false;
struct bpf_tc_hook my_egress_tc_hook;
struct bpf_tc_hook my_ingress_tc_hook;

struct bpf_tc_opts my_egress_tc_opts;
struct bpf_tc_opts my_ingress_tc_opts;

long long totalRTT = 0, totalRNST1 = 0, totalCNST = 0, totalRNST2 = 0;
long long RTTAlerts = 0, RNST1Alerts = 0, CNSTAlerts = 0, RNST2Alerts = 0;
long long dpa_RTT = 0, dpa_RNST1 = 0;
dpa_CNST = 0;
dpa_RNST2 = 0;
long long cpa_RTT = 0, cpa_RNST1 = 0;
cpa_CNST = 0;
cpa_RNST2 = 0;
long long running_RTT = 0, running_RNST1 = 0;
running_CNST = 0;
running_RNST2 = 0;
char iface[32];
int X = 5; // Number that decides whether to send the list of reports to controller or not
// unsigned int ifindex = 65535;
unsigned int ifindex = 8;
uint64_t pkt_counter = 0;
struct hashmap *flowmap;

char xflow_pin_base_dir[] = "/sys/fs/bpf/";
char flow_seq_timestamp_map_name[] = "flow_seq_timestamp_map";
char flow_report_map_name[] = "flow_report_map";
char flow_CNS_rtt_map_name[] = "flow_CNS_rtt_map";
char per_flow_inward_RNS_time_map_name[] = "per_flow_inward_RNS_time_map";
char per_flow_outward_RNS_time_map_name[] = "per_flow_outward_RNS_time_map";
char pod_IP_to_DC_IP_map_name[] = "pod_IP_to_DC_IP_map";
char perf_event_map_name[] = "perf_event_map";
struct event
{
    int pid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

static void tc_cleanup()
{
    int err;
    // err = bpf_tc_detach(&my_tc_hook, &my_tc_opts);
    //  if (err != 0) {
    //      fprintf(stderr, "Failed to detach, err=%s\n", strerror(err));
    //      return 1;
    //  }
    err = bpf_tc_hook_destroy(&my_egress_tc_hook);
    if (err != 0)
    {
        fprintf(stderr, "Failed to destroy tc hook, err=%s\n", strerror(err));
        printf("failed to destroye hooks\n");
    }
    err = bpf_tc_hook_destroy(&my_ingress_tc_hook);
    if (err != 0)
    {
        fprintf(stderr, "Failed to destroy tc hook, err=%s\n", strerror(err));
        printf("failed to destroye hooks\n");
    }
    printf("Destroyed all hooks\n");
}

static void map_cleanup()
{
    int flow_seq_timestamp_map;
    int flow_report_map;
    int per_flow_RNS_map;
    int flow_CNS_map;
    int podIP_to_dcIP_map;

    flow_id_seq curr_flow_seq_key = {};
    flow_id_seq first_flow_seq_key;
    flow_id_seq next_flow_seq_key;

    flow_def *curr_flow_key = NULL;
    flow_def first_flow_key;
    flow_def next_flow_key;

    timestamps seq_timestamps;
    skbAddr *curr_key = NULL;
    skbAddr first_key;
    skbAddr next_key;

    flow_seq_timestamp_map = open_bpf_map_file(xflow_pin_base_dir, flow_seq_timestamp_map_name, NULL);
    if (flow_seq_timestamp_map < 0)
    {
        fprintf(stderr, "ERR: opening map\n");
        printf("Error opening flow_seq_timestamp_map\n");
        return EXIT_FAIL_BPF;
    }
    printf("Clearing map entries from flow_seq_timestamp_map\n\n");

    // get first key and then iterate over and delete the current key after getting the next key.
    if (bpf_map_get_next_key(flow_seq_timestamp_map, &curr_flow_seq_key, &first_flow_seq_key) == 0)
    {
        printf("got the first entry of flow_seq_timestamp_map");
        memcpy(&curr_flow_seq_key, &first_flow_seq_key, sizeof(flow_id_seq));
        while (bpf_map_get_next_key(flow_seq_timestamp_map, &curr_flow_seq_key, &next_flow_seq_key) == 0)
        {
            bpf_map_delete_elem(flow_seq_timestamp_map, &curr_flow_seq_key);
            memcpy(&curr_flow_seq_key, &next_flow_seq_key, sizeof(flow_id_seq));
        }
        // deleting last entry
        bpf_map_delete_elem(flow_seq_timestamp_map, &curr_flow_seq_key);
    }

    //    printf("Deleted entries from flow_seq_timestamp_map\n");

    printf("Clearing map entries from flow_report_map\n");
    flow_report_map = open_bpf_map_file(xflow_pin_base_dir, flow_report_map_name, NULL);
    if (flow_seq_timestamp_map < 0)
    {
        fprintf(stderr, "ERR: opening map\n");
        printf("Error opening flow_report_map\n");
        return EXIT_FAIL_BPF;
    }

    // get the first key
    if (bpf_map_get_next_key(flow_report_map, curr_flow_key, &first_flow_key) == 0)
    {
        curr_flow_key = &first_flow_key;
        while (bpf_map_get_next_key(flow_report_map, curr_flow_key, &next_flow_key) == 0)
        {
            bpf_map_delete_elem(flow_report_map, curr_flow_key);
            curr_flow_key = &next_flow_key;
        }
        bpf_map_delete_elem(flow_report_map, curr_flow_key);
    }

    printf("Clearing map entries from per_inward_flow_RNS_map\n");
    per_flow_RNS_map = open_bpf_map_file(xflow_pin_base_dir, per_flow_inward_RNS_time_map_name, NULL);
    if (per_flow_RNS_map < 0)
    {
        fprintf(stderr, "ERR: opening map\n");
        printf("Error opening flow_RNS_time_map\n");
        return EXIT_FAIL_BPF;
    }
    // get the first entry
    if (bpf_map_get_next_key(per_flow_RNS_map, curr_key, &first_key) == 0)
    {
        curr_key = &first_key;
        while (bpf_map_get_next_key(per_flow_RNS_map, curr_key, &next_key) == 0)
        {
            bpf_map_delete_elem(per_flow_RNS_map, curr_key);
            curr_key = &next_key;
        }
        bpf_map_delete_elem(per_flow_RNS_map, curr_key);
    }
    //    printf("Deleted map entries from per_flow_RNS_map\n");

    printf("Clearing map entries from per_flow_RNS_map\n");
    per_flow_RNS_map = open_bpf_map_file(xflow_pin_base_dir, per_flow_outward_RNS_time_map_name, NULL);
    if (per_flow_RNS_map < 0)
    {
        fprintf(stderr, "ERR: opening map\n");
        printf("Error opening flow_RNS_time_map\n");
        return EXIT_FAIL_BPF;
    }
    // get the first entry
    if (bpf_map_get_next_key(per_flow_RNS_map, curr_key, &first_key) == 0)
    {
        curr_key = &first_key;
        while (bpf_map_get_next_key(per_flow_RNS_map, curr_key, &next_key) == 0)
        {
            bpf_map_delete_elem(per_flow_RNS_map, curr_key);
            curr_key = &next_key;
        }
        bpf_map_delete_elem(per_flow_RNS_map, curr_key);
    }
    //    printf("Deleted map entries from per_flow_RNS_map\n");

    printf("Clearing map entries from flow_CNS_rtt_map_name\n");

    //    flow_id_seq flow_seq_key1 = {};
    //   flow_id_seq next_flow_seq_key1;
    flow_CNS_map = open_bpf_map_file(xflow_pin_base_dir, flow_CNS_rtt_map_name, NULL);
    if (flow_CNS_map < 0)
    {
        fprintf(stderr, "ERR: opening map\n");
        printf("Error opening flow_CNS_rtt_map\n");
        return EXIT_FAIL_BPF;
    }

    // get the first entry
    memset(&curr_flow_seq_key, 0, sizeof(flow_id_seq));
    if (bpf_map_get_next_key(flow_CNS_map, &curr_flow_seq_key, &first_flow_seq_key) == 0)
    {
        memcpy(&curr_flow_seq_key, &first_flow_seq_key, sizeof(flow_id_seq));
        while (bpf_map_get_next_key(flow_CNS_map, &curr_flow_seq_key, &next_flow_seq_key) == 0)
        {
            bpf_map_delete_elem(flow_CNS_map, &curr_flow_seq_key);
            memcpy(&curr_flow_seq_key, &next_flow_seq_key, sizeof(flow_id_seq));
        }
        // delete the last entry
        bpf_map_delete_elem(flow_CNS_map, &curr_flow_seq_key);
    }
    printf("Deleted map entries from flow_CNS_rtt_map_name\n");

    podIP_to_dcIP_map = open_bpf_map_file(xflow_pin_base_dir, pod_IP_to_DC_IP_map_name, NULL);
    if (podIP_to_dcIP_map < 0)
    {
        fprintf(stderr, "ERR: opening map\n");
        printf("Error opening pod_IP_to_DC_IP_map\n");
        return EXIT_FAIL_BPF;
    }

    printf("Clearing map entries of podIP_to_dcIP_map\n");
    curr_key = NULL;
    if (bpf_map_get_next_key(podIP_to_dcIP_map, curr_key, &first_key) == 0)
    {
        curr_key = &first_key;
        while (bpf_map_get_next_key(podIP_to_dcIP_map, curr_key, &next_key) == 0)
        {
            bpf_map_delete_elem(podIP_to_dcIP_map, curr_key);
            curr_key = &next_key;
        }
    }
    printf("Deleted map entries of podIP_to_dcIP_map\n");
}

static void sig_handler(int sig)
{
    printf("Total Alerts from DPA -  RTT: %lld\t RNST1: %lld\t CNST: %lld\t RNST2: %lld\t\n",
           dpa_RTT, dpa_RNST1, dpa_CNST, dpa_RNST2);
    printf("Valid Alerts considered from CPA RTT  : %lld\t RNST1: %lld\t CNST: %lld\t RNST2: %lld\t\n",
           cpa_RTT, cpa_RNST1, cpa_CNST, cpa_RNST2);
    //    printf("Valid Alerts considered from CPA RTT  : %lld\t RNST1: %lld\t CNST: %lld\t RNST2: %lld\t\n",
    //   totalRTT, totalRNST1, totalCNST, totalRNST2);
    //    printf("\nAlert packets send to central controller - RTT : %lld\t RNST1 : %lld\t CNST : %lld\t RNST2 : %lld\t\n",
    //  RTTAlerts, RNST1Alerts, CNSTAlerts, RNST2Alerts);
    printf("Cleaning up..\n");
    tc_cleanup();
    map_cleanup();

    exiting = true;
    exit(1);
}

void bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new))
    {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }
}

int flow_compare(const void *a, const void *b, void *udata)
{
    const flow_record *my_flow_record1 = a;
    const flow_record *my_flow_record2 = b;
    if (my_flow_record1->id.saddr == my_flow_record2->id.saddr &&
        my_flow_record1->id.daddr == my_flow_record2->id.daddr &&
        my_flow_record1->id.sport == my_flow_record2->id.sport &&
        my_flow_record1->id.dport == my_flow_record2->id.dport &&
        my_flow_record1->id.protocol == my_flow_record2->id.protocol &&
        my_flow_record1->id.interface == my_flow_record2->id.interface)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

bool flow_iter(const void *item, void *udata)
{
    const flow_record *my_flow_record = item;
    char saddr_string[32];
    char daddr_string[32];
    char proto_string[10];
    get_ip_string(my_flow_record->id.saddr, saddr_string);
    get_ip_string(my_flow_record->id.daddr, daddr_string);
    get_proto_string(my_flow_record->id.protocol, proto_string);

    printf("%llu | %llu | %llu | %s | %s:%d | %s:%d | %d | %lld\n",
           my_flow_record->counters.pkt_counter,
           my_flow_record->counters.flow_start_ns,
           my_flow_record->counters.flow_end_ns,
           proto_string,
           saddr_string,
           ntohs(my_flow_record->id.sport),
           daddr_string,
           ntohs(my_flow_record->id.dport),
           my_flow_record->counters.packets,
           my_flow_record->counters.bytes);
    return true;
}

uint64_t flow_hash(const void *item, uint64_t seed0, uint64_t seed1)
{
    const flow_record *my_flow_record = item;
    return hashmap_sip(&my_flow_record->id, sizeof(flow_id), seed0, seed1);
}

int handle_event(void *ctx, void *data, size_t data_sz)
{
    // printf("handle_event\n");

    const flow_record *my_flow_record = data;

    hashmap_set(flowmap, my_flow_record);
    pkt_counter++;

    // if (my_flow_record->counters.pkt_counter - pkt_counter != 1) {
    //     printf("Potential Drop!!\n");
    // }
    // pkt_counter = my_flow_record->counters.pkt_counter;
    // printf("%lu.. %lu\n", my_flow_record->counters.pkt_counter, pkt_counter);

    return 0;
}

void print_usage()
{
    printf("./xflow_ringbuf_test_user -i <interface> \n");
}

static const struct option long_options[] = {
    {"interface", required_argument, 0, 'i'},
    {0, 0, NULL, 0}};

int parse_params(int argc, char *argv[])
{
    int opt = 0;
    int long_index = 0;

    while ((opt = getopt_long(argc, argv, "i:",
                              long_options, &long_index)) != -1)
    {
        switch (opt)
        {
        case 'i':
            strncpy(iface, optarg, 32);
            ifindex = if_nametoindex(iface);
            break;
        default:
            print_usage();
            exit(EXIT_FAILURE);
        }
    }
    return 0;
}
/*
void dump_flow_seq_timestamp()
{
    int flow_seq_timestamp_map;
    flow_id_seq flow_key = {};
    flow_id_seq next_flow_key;
    timestamps seq_timestamps;

    char saddr_string[32];
    char daddr_string[32];
    flow_seq_timestamp_map = open_bpf_map_file(xflow_pin_base_dir, flow_seq_timestamp_map_name, NULL);
    if (flow_seq_timestamp_map < 0)
    {
        fprintf(stderr, "ERR: opening map\n");
        return EXIT_FAIL_BPF;
    }
    printf("------------------------------------------------------------------------------------------\n");
    printf("| Src IP Addr:Port  |  Dst IP Addr:Port  |     Seq       |   Send Timestamp   |   RTT  |\n");
    printf("------------------------------------------------------------------------------------------\n");
    while (bpf_map_get_next_key(flow_seq_timestamp_map, &flow_key, &next_flow_key) == 0)
    {
        bpf_map_lookup_elem(flow_seq_timestamp_map, &next_flow_key, &seq_timestamps);
        get_ip_string(next_flow_key.id.saddr, saddr_string);
        get_ip_string(next_flow_key.id.daddr, daddr_string);
        printf("| %s:%d | %s:%d |     %u     |     %llu     |     %u     |\n",
               saddr_string,
               ntohs(next_flow_key.id.sport),
               daddr_string,
               ntohs(next_flow_key.id.dport),
               ntohl(next_flow_key.seq),
               seq_timestamps.send_tstamp,
               seq_timestamps.rtt);
        flow_key = next_flow_key;
    }
}
*/
void dump_flow_reports()
{
    int flow_report_map;
    flow_id_seq flow_key = {};
    flow_id_seq next_flow_key;
    flow_report my_flow_report;

    char saddr_string[32];
    char daddr_string[32];
    flow_report_map = open_bpf_map_file(xflow_pin_base_dir, flow_report_map_name, NULL);
    if (flow_report_map < 0)
    {
        fprintf(stderr, "ERR: opening map\n");
        return EXIT_FAIL_BPF;
    }

    printf("------------------------------------------------------------------------------------------------------------\n");
    printf("| Src IP Addr:Port  |  Dst IP Addr:Port  |     Avg RTT     |    Avg RNST1       |   Avg CNST   |   Avg RNST2\n\n");
    printf("------------------------------------------------------------------------------------------------------------\n");
    while (bpf_map_get_next_key(flow_report_map, &flow_key, &next_flow_key) == 0)
    {
        bpf_map_lookup_elem(flow_report_map, &next_flow_key, &my_flow_report);
        get_ip_string(next_flow_key.id.saddr, saddr_string);
        get_ip_string(next_flow_key.id.daddr, daddr_string);
        printf("| %s:%d | %s:%d | %u | %u | %u | %u\n",
               saddr_string,
               ntohs(next_flow_key.id.sport),
               daddr_string,
               ntohs(next_flow_key.id.dport),
               my_flow_report.avg_rtt,
               my_flow_report.avg_rnst1,
               my_flow_report.avg_cnst,
               my_flow_report.avg_rnst2);
        flow_key = next_flow_key;
    }
}
/*
void dump_RNS_time() {
    int node_RNS_time_map;
    nodeRNSTimestamp nodeRNStstamp;
    __u32 key = 0;

    node_RNS_time_map = open_bpf_map_file(xflow_pin_base_dir, node_RNS_time_map_name, NULL);
    if (node_RNS_time_map < 0) {
        fprintf(stderr,"ERR: opening map\n");
        return EXIT_FAIL_BPF;
    }
    printf("\n-----------------\n");
    printf("  Elapsed Time   \n");
    printf("-----------------\n");
    bpf_map_lookup_elem(node_RNS_time_map, &key, &nodeRNStstamp);
    printf("key 0 - %lu", nodeRNStstamp.tstamp);
    key = 1;
    bpf_map_lookup_elem(node_RNS_time_map, &key, &nodeRNStstamp);
    printf("key 1 - %lu", nodeRNStstamp.tstamp);

}
*/

// void tracing()
// {
//     mongoc_client_t *client;
//     mongoc_collection_t *collection;
//     bson_error_t error;
//     bson_oid_t oid;
//     mongoc_cursor_t *cursor;
//     bson_t *doc;
//     mongoc_init();
//     int per_flow_RNS_map;
//     int flow_CNS_map;
//     int podIP_to_dcIP_map;
//     int threshold = 90000;
//     int flow_report_map;
//     flow_id_seq flow_key = {};
//     flow_id_seq next_flow_key;
//     flow_report my_flow_report;
//     skbAddr skbuff_addr;
//     flow_def dc_flow_id;
//     flow_def pod_flow_id;
//     char saddr_string[32];
//     char daddr_string[32];

//     client = mongoc_client_new("mongodb://localhost:27017/?appname=insert-example");
//     collection = mongoc_client_get_collection(client, "mydb", "mycoll");
//     flow_report_map = open_bpf_map_file(xflow_pin_base_dir, flow_report_map_name, NULL);
//     if (flow_report_map < 0)
//     {
//         fprintf(stderr, "ERR: opening map\n");
//         printf("Error opening flow_report_map\n");
//         return EXIT_FAIL_BPF;
//     }
//     podIP_to_dcIP_map = open_bpf_map_file(xflow_pin_base_dir, pod_IP_to_DC_IP_map_name, NULL);
//     if (podIP_to_dcIP_map < 0)
//     {
//         fprintf(stderr, "ERR: opening map\n");
//         printf("Error opening pod_IP_to_DC_IP_map\n");
//         return EXIT_FAIL_BPF;
//     }
//     while (bpf_map_get_next_key(flow_report_map, &flow_key, &next_flow_key) == 0)
//     {
//         bpf_map_lookup_elem(flow_report_map, &next_flow_key, &my_flow_report);
//         if (my_flow_report.avg_rtt > threshold || my_flow_report.avg_rnst1 > threshold || my_flow_report.avg_cnst > threshold)
//         {
//             get_ip_string(next_flow_key.id.saddr, saddr_string);
//             get_ip_string(next_flow_key.id.daddr, daddr_string);
//             bson_t *query;
//             doc = bson_new();
//             query = bson_new();
//             bson_oid_init(&oid, NULL);
//             BSON_APPEND_OID(doc, "_id", &oid);
//             BSON_APPEND_UTF8(doc, "src_ip", saddr_string);
//             BSON_APPEND_UTF8(doc, "dst_ip", daddr_string);
//             BSON_APPEND_INT32(doc, "src_port", ntohs(next_flow_key.id.sport));
//             BSON_APPEND_INT32(doc, "dst_port", ntohs(next_flow_key.id.dport));
//             BSON_APPEND_INT32(doc, "avg_rtt", my_flow_report.avg_rtt);
//             BSON_APPEND_INT32(doc, "avg_rnst1", my_flow_report.avg_rnst1);
//             BSON_APPEND_INT32(doc, "avg_cnst", my_flow_report.avg_cnst);
//             //  bpf_map_lookup_elem(podIP_to_dcIP_map, &next_flow_key, &dc_flow_id)
//             //  BSON_APPEND_UTF8(doc, "src_pod", saddr_string);
//             //  BSON_APPEND_UTF8(doc, "dst_pod",daddr_string);
//             //  BSON_APPEND_UTF8(doc, "src_dc", dc_flow_id.saddr);
//             //  BSON_APPEND_UTF8(doc, "dst_dc", dc_flow_id.daddr);
//             cursor = mongoc_collection_find_with_opts(collection, query, NULL, NULL);

//             if (!mongoc_collection_insert_one(collection, doc, NULL, NULL, &error))
//             {
//                 fprintf(stderr, "%s\n", error.message);
//             }
//             char *str;
//             //             while (mongoc_cursor_next(cursor, &doc))
//             //           {
//             //             str = bson_as_canonical_extended_json(doc, NULL);
//             //           // printf("%s\n", str);
//             //         bson_free(str);
//             //   }
//             bson_destroy(doc);
//         }

//         flow_key = next_flow_key;
//     }
//     mongoc_collection_destroy(collection);
//     mongoc_client_destroy(client);
//     mongoc_cleanup();
// }
void *print_flows(void *ptr)
{
    while (1)
    {
        //        dump_flow_seq_timestamp();
        //        sleep(1);
        dump_flow_reports();
        // tracing();
        sleep(1);
        //	dump_RNS_time();
        //       sleep(1);
        // printf("------------------------------------------------------------------------------------------\n");
        // printf("| Src IP Addr:Port  |  Dst IP Addr:Port  |     Seq       |   Send Timestamp   |   RTT |\n");
        // printf("------------------------------------------------------------------------------------------\n");
    }
}

ringbuf_data_tstamp *rtt_flow_array = NULL;
ringbuf_data_tstamp *rnst1_flow_array = NULL;
ringbuf_data_tstamp *cnst_flow_array = NULL;
ringbuf_data_tstamp *rnst2_flow_array = NULL;
long long nRTT = 0, nRNST1 = 0, nCNST = 0, nRNST2 = 0;

bool timerRunning = false;        // Flag to check if the timer is running
bool coolOffTimerRunning = false; // Flag to check if the cool off timer is running

// void structToString(const ringbuf_data_tstamp *data, char *str, size_t maxLen) {
//     // Convert network byte order to host byte order
//     __u32 saddr = ntohl(data->saddr);
//     __u32 daddr = ntohl(data->daddr);
//     __u16 sport = ntohs(data->sport);
//     __u16 dport = ntohs(data->dport);
//     __u16 type = ntohs(data->type);

//     // Convert IP addresses to string format
//     char saddr_str[INET_ADDRSTRLEN];
//     char daddr_str[INET_ADDRSTRLEN];
//     inet_ntop(AF_INET, &saddr, saddr_str, INET_ADDRSTRLEN);
//     inet_ntop(AF_INET, &daddr, daddr_str, INET_ADDRSTRLEN);

//     snprintf(str, maxLen, "%llu,%s,%s,%u,%u,%u,%u",
//              (unsigned long long)data->tstamp, saddr_str, daddr_str,
//              data->value, sport, dport, type);
// }

void *sendToController()
{

    // UDP socket setup
    int udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket < 0)
    {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(12345);                       // Destination port number
    serverAddr.sin_addr.s_addr = inet_addr("192.168.50.150"); // Destination IP address
    char bigBuffer[60000];                                    // Large buffer to hold the maximum UDP payload
    int currentBufferSize = 0;

    if (nRTT > X)
    {
        totalRTT += nRTT;
        RTTAlerts++;
        printf("\nnRTT: %d", nRTT);

        long long i = 0;
        memset(bigBuffer, 0, sizeof(bigBuffer));
        currentBufferSize = 0;

        while (i < nRTT)
        {
            char saddr_string[16];
            char daddr_string[16];
            char buffer[100];
            get_ip_string(rtt_flow_array[i].saddr, saddr_string);
            get_ip_string(rtt_flow_array[i].daddr, daddr_string);
            sprintf(buffer, "|%s:%d|%s:%d|%u|%u|%d|%d|%ld|\n",
                    saddr_string,
                    ntohs(rtt_flow_array[i].sport),
                    daddr_string,
                    ntohs(rtt_flow_array[i].dport),
                    rtt_flow_array[i].type,
                    rtt_flow_array[i].value,
                    rtt_flow_array[i].ackNo,
                    rtt_flow_array[i].seqNo,
                    rtt_flow_array[i].tstamp);

            // Check if the buffer can be added without exceeding max UDP payload size
            if (currentBufferSize + strlen(buffer) < sizeof(bigBuffer))
            {
                strcat(bigBuffer, buffer); // Append buffer to bigBuffer
                currentBufferSize += strlen(buffer);
            }
            else
            {
                // Send the bigBuffer if adding the next buffer would exceed the size limit
                ssize_t bytesSent = sendto(udpSocket, bigBuffer, currentBufferSize, 0, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
                if (bytesSent < 0)
                {
                    perror("Error sending data");
                    close(udpSocket);
                    exit(EXIT_FAILURE);
                }
                // Reset bigBuffer for the next batch of data
                memset(bigBuffer, 0, sizeof(bigBuffer));
                currentBufferSize = 0;
                strcat(bigBuffer, buffer);
                currentBufferSize += strlen(buffer);
            }
            i++;
        }

        // Send any remaining data in bigBuffer
        if (currentBufferSize > 0)
        {
            ssize_t bytesSent = sendto(udpSocket, bigBuffer, currentBufferSize, 0, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
            if (bytesSent < 0)
            {
                perror("Error sending data");
                close(udpSocket);
                exit(EXIT_FAILURE);
            }
        }
    }

    if (nRNST1 > X)
    {
        totalRNST1 += nRNST1;
        RNST1Alerts++;
        printf("\nnRNST1: %d", nRNST1);

        long long i = 0;
        memset(bigBuffer, 0, sizeof(bigBuffer));
        currentBufferSize = 0;

        while (i < nRNST1)
        {
            char saddr_string[16];
            char daddr_string[16];
            char buffer[100];
            get_ip_string(rnst1_flow_array[i].saddr, saddr_string);
            get_ip_string(rnst1_flow_array[i].daddr, daddr_string);
            sprintf(buffer, "|%s:%d|%s:%d|%u|%u|%d|%d|%ld|\n",
                    saddr_string,
                    ntohs(rnst1_flow_array[i].sport),
                    daddr_string,
                    ntohs(rnst1_flow_array[i].dport),
                    rnst1_flow_array[i].type,
                    rnst1_flow_array[i].value,
                    rnst1_flow_array[i].ackNo,
                    rnst1_flow_array[i].seqNo,
                    rnst1_flow_array[i].tstamp);
            // Check if the buffer can be added without exceeding max UDP payload size
            if (currentBufferSize + strlen(buffer) < sizeof(bigBuffer))
            {
                strcat(bigBuffer, buffer); // Append buffer to bigBuffer
                currentBufferSize += strlen(buffer);
            }
            else
            {
                // Send the bigBuffer if adding the next buffer would exceed the size limit
                ssize_t bytesSent = sendto(udpSocket, bigBuffer, currentBufferSize, 0, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
                if (bytesSent < 0)
                {
                    perror("Error sending data");
                    close(udpSocket);
                    exit(EXIT_FAILURE);
                }
                // Reset bigBuffer for the next batch of data
                memset(bigBuffer, 0, sizeof(bigBuffer));
                currentBufferSize = 0;
                strcat(bigBuffer, buffer);
                currentBufferSize += strlen(buffer);
            }
            i++;
        }

        // Send any remaining data in bigBuffer
        if (currentBufferSize > 0)
        {
            ssize_t bytesSent = sendto(udpSocket, bigBuffer, currentBufferSize, 0, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
            if (bytesSent < 0)
            {
                perror("Error sending data");
                close(udpSocket);
                exit(EXIT_FAILURE);
            }
        }
    }

    if (nCNST > X)
    {
        totalCNST += nCNST;
        CNSTAlerts++;
        printf("\nnCNST: %d", nCNST);

        long long i = 0;
        memset(bigBuffer, 0, sizeof(bigBuffer));
        currentBufferSize = 0;

        while (i < nCNST)
        {
            char saddr_string[16];
            char daddr_string[16];
            char buffer[100];
            get_ip_string(cnst_flow_array[i].saddr, saddr_string);
            get_ip_string(cnst_flow_array[i].daddr, daddr_string);
            sprintf(buffer, "|%s:%d|%s:%d|%u|%u|%d|%d|%ld|\n",
                    saddr_string,
                    ntohs(cnst_flow_array[i].sport),
                    daddr_string,
                    ntohs(cnst_flow_array[i].dport),
                    cnst_flow_array[i].type,
                    cnst_flow_array[i].value,
                    cnst_flow_array[i].ackNo,
                    cnst_flow_array[i].seqNo,
                    cnst_flow_array[i].tstamp);

            // Check if the buffer can be added without exceeding max UDP payload size
            if (currentBufferSize + strlen(buffer) < sizeof(bigBuffer))
            {
                strcat(bigBuffer, buffer); // Append buffer to bigBuffer
                currentBufferSize += strlen(buffer);
            }
            else
            {
                // Send the bigBuffer if adding the next buffer would exceed the size limit
                ssize_t bytesSent = sendto(udpSocket, bigBuffer, currentBufferSize, 0, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
                if (bytesSent < 0)
                {
                    perror("Error sending data");
                    close(udpSocket);
                    exit(EXIT_FAILURE);
                }
                // Reset bigBuffer for the next batch of data
                memset(bigBuffer, 0, sizeof(bigBuffer));
                currentBufferSize = 0;
                strcat(bigBuffer, buffer);
                currentBufferSize += strlen(buffer);
            }
            i++;
        }

        // Send any remaining data in bigBuffer
        if (currentBufferSize > 0)
        {
            ssize_t bytesSent = sendto(udpSocket, bigBuffer, currentBufferSize, 0, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
            if (bytesSent < 0)
            {
                perror("Error sending data");
                close(udpSocket);
                exit(EXIT_FAILURE);
            }
        }
    }
    if (nRNST2 > X)
    {
        totalRNST2 += nRNST2;
        RNST2Alerts++;
        printf("\nnRNST2: %d", nRNST2);

        long long i = 0;
        memset(bigBuffer, 0, sizeof(bigBuffer));
        currentBufferSize = 0;

        while (i < nRNST2)
        {
            char saddr_string[16];
            char daddr_string[16];
            char buffer[100];
            get_ip_string(rnst2_flow_array[i].saddr, saddr_string);
            get_ip_string(rnst2_flow_array[i].daddr, daddr_string);
            sprintf(buffer, "|%s:%d|%s:%d|%u|%u|%d|%d|%ld|\n",
                    saddr_string,
                    ntohs(rnst2_flow_array[i].sport),
                    daddr_string,
                    ntohs(rnst2_flow_array[i].dport),
                    rnst2_flow_array[i].type,
                    rnst2_flow_array[i].value,
                    rnst2_flow_array[i].ackNo,
                    rnst2_flow_array[i].seqNo,
                    rnst2_flow_array[i].tstamp);

            // Check if the buffer can be added without exceeding max UDP payload size
            if (currentBufferSize + strlen(buffer) < sizeof(bigBuffer))
            {
                strcat(bigBuffer, buffer); // Append buffer to bigBuffer
                currentBufferSize += strlen(buffer);
            }
            else
            {
                // Send the bigBuffer if adding the next buffer would exceed the size limit
                ssize_t bytesSent = sendto(udpSocket, bigBuffer, currentBufferSize, 0, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
                if (bytesSent < 0)
                {
                    perror("Error sending data");
                    close(udpSocket);
                    exit(EXIT_FAILURE);
                }
                // Reset bigBuffer for the next batch of data
                memset(bigBuffer, 0, sizeof(bigBuffer));
                currentBufferSize = 0;
                strcat(bigBuffer, buffer);
                currentBufferSize += strlen(buffer);
            }
            i++;
        }

        // Send any remaining data in bigBuffer
        if (currentBufferSize > 0)
        {
            ssize_t bytesSent = sendto(udpSocket, bigBuffer, currentBufferSize, 0, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
            if (bytesSent < 0)
            {
                perror("Error sending data");
                close(udpSocket);
                exit(EXIT_FAILURE);
            }
        }
    }
    nRTT = 0;
    nRNST1 = 0;
    nCNST = 0;
    nRNST2 = 0;
    free(rtt_flow_array);
    free(rnst1_flow_array);
    free(cnst_flow_array);
    free(rnst2_flow_array);
    rtt_flow_array = NULL;
    rnst1_flow_array = NULL;
    cnst_flow_array = NULL;
    rnst2_flow_array = NULL;
    // Close the socket
    close(udpSocket);
    // close(tcpSocket);

    return NULL;
}

void *coolOffTimer(void *arg)
{

    pthread_t sendToControllerThread;
    if (pthread_create(&sendToControllerThread, NULL, sendToController, NULL) != 0)
    {
        fprintf(stderr, "Error creating Send to controller thread.\n");
        exit(1);
    }

    int coolOffTimerDuration = 3;
    sleep(coolOffTimerDuration);
    pthread_join(sendToControllerThread, NULL);
    coolOffTimerRunning = false;
    // printf("Cool-off timer expired.\n");

    return NULL;
}

void *timer(void *arg)
{

    // printf("\nTimer started");
    int seconds = 3;
    sleep(seconds);

    // Timer expires
    //  printf("Timer Expires\n");
    dpa_RTT = dpa_RTT + nRTT;
    dpa_RNST1 = dpa_RNST1 + nRNST1;
    dpa_CNST = dpa_CNST + nCNST;
    dpa_RNST2 = dpa_RNST2 + nRNST2;
    //    printf("Total Alerts from DPA in the interval -  RTT  : %lld\t RNST1: %lld\t CNST: %lld\t RNST2: %lld\t\n",nRTT, nRNST1, nCNST, nRNST2);
    //  if(nRTT > X || nRNST1 > X || nCNST > X || nRNST2 > X){
    int flag = 0;
    if (nRTT > X)
    {
        flag = 1;
        cpa_RTT = cpa_RTT + nRTT;
    }
    if (nRNST1 > X)
    {
        flag = 1;
        cpa_RNST1 = cpa_RNST1 + nRNST1;
    }
    if (nCNST > X)
    {
        flag = 1;
        cpa_CNST = cpa_CNST + nCNST;
    }
    if (nRNST2 > X)
    {
        flag = 1;
        cpa_RNST2 = cpa_RNST2 + nRNST2;
    }
    if (flag)
    {
        /*time_t current_time;
        // Get the current time
        current_time = time(NULL);
        // Print the current time as an integer representing the number of seconds since the Unix epoch
        printf("TimeStamp: %ld\n", (long)current_time);*/

        struct timespec ts;

        // Get the current time
        clock_gettime(CLOCK_REALTIME, &ts);

        // Calculate the total time in nanoseconds
        long long total_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec;

        // Print the total time in nanoseconds
        printf("TimeStamp: %lld ns\n", total_ns);
    }

    // printf("Cool-off timer started\n");

    // Start cool-off timer in a separate thread
    /*    int coolOffTimerDuration = 3;  // Set the cool-off timer duration (in seconds)
        coolOffTimerRunning = true;
        pthread_t coolOffThread;
        if (pthread_create(&coolOffThread, NULL, coolOffTimer, NULL) != 0) {
            fprintf(stderr, "Error creating cool-off timer thread.\n");
            exit(1);
        }
        pthread_join(coolOffThread, NULL);
*/
    // commenting temporarily
    /*
             pthread_t sendToControllerThread;
             if (pthread_create(&sendToControllerThread, NULL, sendToController, NULL) != 0) {
                 fprintf(stderr, "Error creating Send to controller thread.\n");
                 exit(1);
             }*/
    //         pthread_join(sendToControllerThread, NULL);

    //}
    timerRunning = false;
    return NULL;
}

void *print_alerts(void *ptr)
{
    int count = 1;
    while (1)
    {
        sleep(1);
        printf("Total Alerts from DPA in the %d second -  RTT  : %lld\t RNST1: %lld\t CNST: %lld\t RNST2: %lld\t\n", count, running_RTT, running_RNST1, running_CNST, running_RNST2);
        printf("Total Alerts from CPA in the %d second -  RTT  : %lld\t RNST1: %lld\t CNST: %lld\t RNST2: %lld\t\n", count, cpa_RTT, cpa_RNST1, cpa_CNST, cpa_RNST2);
        count++;
    }
}

int handle_ringbuf_event(void *ctx, void *data, int size)
{
    char saddr_string[32];
    char daddr_string[32];

    /*
    if(coolOffTimerRunning){
            // printf("Cool-off timer is running, ignoring the event\n");
            exit;
        }
    */
    if (!timerRunning)
    {
        nRTT = 0;
        nRNST1 = 0;
        nRNST2 = 0;
        nCNST = 0;
        int timerDuration = 3;
        timerRunning = true;
        // Create a thread for the timer
        pthread_t timerThread;
        if (pthread_create(&timerThread, NULL, timer, NULL) != 0)
        {
            fprintf(stderr, "Error creating timer thread.\n");
            exit(1);
        }
        //    pthread_join(timerThread, NULL);
    }

    ringbuf_data *flow_report = data;
    switch (flow_report->type)
    {
    case 1:
        nRTT++;
        running_RTT++;
        break;
    case 2:
        nRNST1++;
        running_RNST1++;
        break;
    case 3:
        nCNST++;
        running_CNST++;
        break;
    case 4:
        nRNST2++;
        running_RNST2++;
        break;
    }

    /*get_ip_string(flow_report->saddr, saddr_string);
     get_ip_string(flow_report->daddr, daddr_string);
         printf("| %s:%d | %s:%d | %u | %u | %u \n",
             saddr_string,
             ntohs(flow_report->sport),
             daddr_string,
             ntohs(flow_report->dport),
             flow_report->type,
             flow_report->value,
             flow_report->ackNo);*/

    /*
        // Get the current timestamp based on UNIX epoch time
        struct timeval currentTime;
        gettimeofday(&currentTime, NULL);

        // Calculate the timestamp in microseconds
        unsigned long long timestampInMicroseconds = (long long)currentTime.tv_sec * 1000000LL + (long long)currentTime.tv_usec;

        // ringbuf_data_tstamp *flow_report_tstamp = data;
        ringbuf_data_tstamp *flow_report_tstamp;

        // Allocate memory for the structure
        flow_report_tstamp = (ringbuf_data_tstamp *)malloc(sizeof(ringbuf_data_tstamp));
        if (flow_report_tstamp == NULL) {
            fprintf(stderr, "Memory allocation failed.\n");
            return 1;
        }

        flow_report_tstamp->saddr = flow_report->saddr;
        flow_report_tstamp->sport = flow_report->sport;
        flow_report_tstamp->daddr = flow_report->daddr;
        flow_report_tstamp->dport = flow_report->dport;
        flow_report_tstamp->type = flow_report->type;
        flow_report_tstamp->value = flow_report->value;
        flow_report_tstamp->seqNo = flow_report->seqNo;
        flow_report_tstamp->ackNo = flow_report->ackNo;
        flow_report_tstamp->tstamp = timestampInMicroseconds;
    */
    // if(flow_report_tstamp->type == 2 || flow_report_tstamp->type == 4 || flow_report_tstamp->type == 1){
    /*     printf("-----------------------------------------------------------------------------\n");
         printf("| Src IP Addr:Port  |  Dst IP Addr:Port  |     Type    |     value      \n\n");
         printf("-----------------------------------------------------------------------------\n");
         get_ip_string(flow_report_tstamp->saddr, saddr_string);
         get_ip_string(flow_report_tstamp->daddr, daddr_string);
             printf("| %s:%d | %s:%d | %u | %u \n",
                 saddr_string,
                 ntohs(flow_report_tstamp->sport),
                 daddr_string,
                 ntohs(flow_report_tstamp->dport),
                 flow_report_tstamp->type,
                 flow_report_tstamp->value);*/
    //             flow_report_tstamp->tstamp);
    // }

    /*
        if(flow_report_tstamp->type == 1){
            // Allocate memory for the rtt_flow_array or resize it
            nRTT++;
            rtt_flow_array = (ringbuf_data_tstamp*)realloc(rtt_flow_array, nRTT * sizeof(ringbuf_data_tstamp));
            if (rtt_flow_array == NULL) {
                fprintf(stderr, "Memory allocation failed.\n");
                exit(1);
            }
            rtt_flow_array[nRTT - 1] = *flow_report_tstamp;
        }
        else if(flow_report_tstamp->type == 2){
            // Allocate memory for the rnst1_flow_array or resize it
            nRNST1++;
            rnst1_flow_array = (ringbuf_data_tstamp*)realloc(rnst1_flow_array, nRNST1 * sizeof(ringbuf_data_tstamp));
            if (rnst1_flow_array == NULL) {
                fprintf(stderr, "Memory allocation failed.\n");
                exit(1);
            }
            rnst1_flow_array[nRNST1 - 1] = *flow_report_tstamp;
        }
        else if(flow_report_tstamp->type == 3){
            // Allocate memory for the cnst_flow_array or resize it
            nCNST++;
            cnst_flow_array = (ringbuf_data_tstamp*)realloc(cnst_flow_array, nCNST * sizeof(ringbuf_data_tstamp));
            if (cnst_flow_array == NULL) {
                fprintf(stderr, "Memory allocation failed.\n");
                exit(1);
            }
            cnst_flow_array[nCNST - 1] = *flow_report_tstamp;
        }
        else if(flow_report_tstamp->type == 4){
            // Allocate memory for the rnst2_flow_array or resize it
            nRNST2++;
            rnst2_flow_array = (ringbuf_data_tstamp*)realloc(rnst2_flow_array, nRNST2 * sizeof(ringbuf_data_tstamp));
            if (rnst2_flow_array == NULL) {
                fprintf(stderr, "Memory allocation failed.\n");
                exit(1);
            }
            rnst2_flow_array[nRNST2 - 1] = *flow_report_tstamp;
        }

        */
    /*
        //Buffer full
        if(timerRunning && (nRTT+nRNST1+nRNST2+nCNST)*sizeof(ringbuf_data_tstamp) >= 65000){
            timerRunning = false;
            // Start cool-off timer in a separate thread
            int coolOffTimerDuration = 3;  // Set the cool-off timer duration (in seconds)
            coolOffTimerRunning = true;
            pthread_t coolOffThread;
            if (pthread_create(&coolOffThread, NULL, coolOffTimer, NULL) != 0) {
                fprintf(stderr, "Error creating cool-off timer thread.\n");
                exit(1);
            }
            pthread_join(coolOffThread, NULL);
        }
        */
    return 0;
}

int main(int argc, char *argv[])
{
    // printf("Hello Ankit");
    pthread_t flow_scan_thread;
    const char *bpf_file = "rtt.o";
    struct bpf_object *obj;
    int prog_fd = -1;
    int my_egress_prog_fd = -1;
    int my_ingress_prog_fd = -1;

    int buffer_map_fd = -1;
    struct bpf_program *egress_prog;
    struct bpf_program *ingress_prog;

    int err;
    // int interface_ifindex = 4;
    char error[32];
    struct perf_buffer *pb;
    struct ring_buffer *rb;
    int ret;
    int map_fd;

    if (parse_params(argc, argv) != 0)
    {
        fprintf(stderr, "ERR: parsing params\n");
        return EXIT_FAIL_OPTION;
    }

    printf("Running on interface idx-%d\n", ifindex);

    memset(&my_egress_tc_hook, 0, sizeof(my_egress_tc_hook));
    my_egress_tc_hook.sz = sizeof(my_egress_tc_hook);
    my_egress_tc_hook.ifindex = ifindex;
    my_egress_tc_hook.attach_point = BPF_TC_EGRESS;

    memset(&my_ingress_tc_hook, 0, sizeof(my_ingress_tc_hook));
    my_ingress_tc_hook.sz = sizeof(my_ingress_tc_hook);
    my_ingress_tc_hook.ifindex = ifindex;
    my_ingress_tc_hook.attach_point = BPF_TC_INGRESS;

    err = bpf_tc_hook_create(&my_egress_tc_hook);
    if (err != 0)
    {
        if (err == -17)
        {
            // tc_hook already exisits
        }
        else
        {
            libbpf_strerror(err, error, 32);
            fprintf(stderr, "Failed to create tc hook err=%d, %s\n", err, error);
            return 1;
        }
    }

    err = bpf_tc_hook_create(&my_ingress_tc_hook);
    if (err != 0)
    {
        if (err == -17)
        {
            // tc_hook already exisits
        }
        else
        {
            libbpf_strerror(err, error, 32);
            fprintf(stderr, "Failed to create tc hook err=%d, %s\n", err, error);
            return 1;
        }
    }
    /* Bump RLIMIT_MEMLOCK to create BPF maps */
    bump_memlock_rlimit();

    /* Clean handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    err = bpf_prog_load(bpf_file, BPF_PROG_TYPE_SCHED_CLS, &obj, &prog_fd);
    if (err != 0)
    {
        fprintf(stderr, "Failed to load Program\n");
        return 1;
    }

    // Load egress/ingress sections

    egress_prog = bpf_object__find_program_by_title(obj, "xflow_rtt_egress");
    if (!egress_prog)
    {
        fprintf(stderr, "failed to find xflow_rtt_egress \n");
        return 1;
    }
    ingress_prog = bpf_object__find_program_by_title(obj, "xflow_rtt_ingress");
    if (!ingress_prog)
    {
        fprintf(stderr, "failed to find xflow_rtt_ingress\n");
        return 1;
    }

    my_egress_prog_fd = bpf_program__fd(egress_prog);
    if (my_egress_prog_fd <= 0)
    {
        fprintf(stderr, "ERR: bpf_program__fd egress failed\n");
        return 1;
    }
    my_ingress_prog_fd = bpf_program__fd(ingress_prog);
    if (my_ingress_prog_fd <= 0)
    {
        fprintf(stderr, "ERR: bpf_program__fd ingress failed\n");
        return 1;
    }

    memset(&my_egress_tc_opts, 0, sizeof(my_egress_tc_opts));
    my_egress_tc_opts.sz = sizeof(my_egress_tc_opts);
    my_egress_tc_opts.prog_fd = my_egress_prog_fd;

    memset(&my_ingress_tc_opts, 0, sizeof(my_ingress_tc_opts));
    my_ingress_tc_opts.sz = sizeof(my_ingress_tc_opts);
    my_ingress_tc_opts.prog_fd = my_ingress_prog_fd;

    err = bpf_tc_attach(&my_egress_tc_hook, &my_egress_tc_opts);
    if (err != 0)
    {
        fprintf(stderr, "Failed to attach tc program at egress\n");
        return 1;
    }

    err = bpf_tc_attach(&my_ingress_tc_hook, &my_ingress_tc_opts);
    if (err != 0)
    {
        fprintf(stderr, "Failed to attach tc program at ingress\n");
        return 1;
    }
    printf("Attached %s program to tc hook point at ifindex:%d\n", bpf_file, ifindex);
    /*
        map_fd = bpf_object__find_map_fd_by_name(obj, "perf_event_map");

        pb = perf_buffer__new(map_fd, 8, handle_perf_event, NULL, NULL, NULL);
        ret = libbpf_get_error(pb);
        if (ret) {
            printf("failed to setup perf_buffer: %d\n", ret);
            return 1;
        }
        printf("waiting on poll\n");
        while ((ret = perf_buffer__poll(pb, 1000)) >= 0) {
        }
    */
    // printf("Ankit");
    map_fd = bpf_object__find_map_fd_by_name(obj, "ringbuf_map");
    // printf("map-fd: %d", map_fd);
    rb = ring_buffer__new(map_fd, handle_ringbuf_event, NULL, NULL);
    if (!rb)
    {
        printf("failed to setup ring_buffer\n");
        return 1;
    }
    /*thread that print the alerts every one second*/

    pthread_create(&flow_scan_thread, NULL, print_alerts, NULL);
    while ((ret = ring_buffer__poll(rb, 100)) >= 0)
    {
        // printf("number: %d", ret);
    }

    /*
    pthread_create(&flow_scan_thread, NULL, print_flows, NULL);

    // pthread_join(flow_scan_thread, NULL);
    while (1)
    {
        sleep(1);
    }
    */
    return 0;
}
