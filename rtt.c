/*
    An ebpf tc program to calculate avg-RTT for flows based on the TCP Seq/ACK
*/
#include "xflow_global.h"

#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
// we are using tc to load in our ebpf program that will
// create maps for us and require structure bpf_elf_map
#include <iproute2/bpf_elf.h>
#include <bpf/bpf_helpers.h>

#include <bpf/bpf_endian.h>

#include "../common/parsing_helpers.h"
#include "../common/common_defines.h"
#include "../common/common_utils.h"

#define MYNAME "xflow_rtt"
/* *3
#define T1_rtt 826881
#define T2_rtt 2797401
#define T1_rnst1 142917
#define T2_rnst1 71985
#define T1_cnst 5473863
#define T2_cnst 2671560
#define T1_rnst2 142917
#define T2_rnst2 71985
*/
/* *4
#define T1_rtt 1102508
#define T2_rtt 3729868
#define T1_rnst1 190556
#define T2_rnst1 95980
#define T1_cnst 7298484
#define T2_cnst 3562080
#define T1_rnst2 190556
#define T2_rnst2 95980
*/
/* *2.5
#define T1_rtt 689068
#define T2_rtt 2331168
#define T1_rnst1 119098
#define T2_rnst1 59988
#define T1_cnst 4561553
#define T2_cnst 2226300
#define T1_rnst2 119098
#define T2_rnst2 59988
*/

/* *2
#define T1_rtt 551254
#define T2_rtt 1864934
#define T1_rnst1 95278
#define T2_rnst1 47990
#define T1_cnst 3649242
#define T2_cnst 1781040
#define T1_rnst2 95278
#define T2_rnst2 47990
*/
/* * 1.5
#define T1_rtt 413441
#define T2_rtt 1398701
#define T1_rnst1 71459
#define T2_rnst1 35993
#define T1_cnst 2736932
#define T2_cnst 1335780
#define T1_rnst2 71459
#define T2_rnst2 35993
*/
/* Without CPU limit threshold, 100% load, 99% value*/
/* *2
#define T1_rtt 1709780
#define T2_rtt 1500020
#define T1_rnst1 523818
#define T2_rnst1 156618
#define T1_cnst 2943272
#define T2_cnst 1621732
#define T1_rnst2 774676
#define T2_rnst2 36450
*/

/* *2.5
#define T1_rtt 2137225
#define T2_rtt 1875025
#define T1_rnst1 654772
#define T2_rnst1 195772
#define T1_cnst 3679090
#define T2_cnst 2027165
#define T1_rnst2 968345
#define T2_rnst2 45562
*/
/* *3
#define T1_rtt 2564670
#define T2_rtt 2250030
#define T1_rnst1 785727
#define T2_rnst1 234927
#define T1_cnst 4414908
#define T2_cnst 2432598
#define T1_rnst2 1162014
#define T2_rnst2 54675
*/
/* *3.5
#define T1_rtt 2992115
#define T2_rtt 2625035
#define T1_rnst1 916681
#define T2_rnst1 274081
#define T1_cnst 5150726
#define T2_cnst 2838031
#define T1_rnst2 1355683
#define T2_rnst2 63787
*/
/*rtt-2, rnst-4, cnst-6
#define T1_rtt 1709780
#define T2_rtt 1500020
#define T1_rnst1 1047636
#define T2_rnst1 313236
#define T1_cnst 8829816
#define T2_cnst 4865196
#define T1_rnst2 1549352
#define T2_rnst2 72900
*/

/* *4
#define T1_rtt 3419560
#define T2_rtt 3000040
#define T1_rnst1 1047636
#define T2_rnst1 313236
#define T1_cnst 5886544
#define T2_cnst 3243464
#define T1_rnst2 1549352
#define T2_rnst2 72900
*/

/* *5
#define T1_rtt 4274450
#define T2_rtt 3750050
#define T1_rnst1 1309545
#define T2_rnst1 391545
#define T1_cnst 7358180
#define T2_cnst 4054330
#define T1_rnst2 1936690
#define T2_rnst2 91125
*/
/* *10
#define T1_rtt
#define T2_rtt
#define T1_rnst1
#define T2_rnst1
#define T1_cnst
#define T2_cnst
#define T1_rnst2
#define T2_rnst2
*/

/* *6
#define T1_rtt 5129340
#define T2_rtt 4500060
#define T1_rnst1 1571454
#define T2_rnst1 469854
#define T1_cnst 8829816
#define T2_cnst 4865196
#define T1_rnst2 2324028
#define T2_rnst2 109350
*/

/* *8
#define T1_rtt 6839120
#define T2_rtt 6000080
#define T1_rnst1 2095272
#define T2_rnst1 626472
#define T1_cnst 11773088
#define T2_cnst 6486928
#define T1_rnst2 3098704
#define T2_rnst2 145800
*/

/* Without CPU limit threshold*/
/* *2
#define T1_rtt 2955430
#define T2_rtt 512594
#define T1_rnst1 749462
#define T2_rnst1 28574
#define T1_cnst 1402182
#define T2_cnst 498026
#define T1_rnst2 1010778
#define T2_rnst2 25710
*/
/* *2.5
#define T1_rtt 3694288
#define T2_rtt 640743
#define T1_rnst1 936828
#define T2_rnst1 35718
#define T1_cnst 1752728
#define T2_cnst 622533
#define T1_rnst2 1263472
#define T2_rnst2 32138
*/
/* *3
#define T1_rtt 4433145
#define T2_rtt 768891
#define T1_rnst1 1124193
#define T2_rnst1 42861
#define T1_cnst 2103273
#define T2_cnst 747039
#define T1_rnst2 1516167
#define T2_rnst2 38565
*/
/* *4
#define T1_rtt 4912504
#define T2_rtt 963952
#define T1_rnst1 1467712
#define T2_rnst1 56948
#define T1_cnst 2676092
#define T2_cnst 920752
#define T1_rnst2 1917368
#define T2_rnst2 51500
*/

/* *9
#define T1_rtt 11053134
#define T2_rtt 2168892
#define T1_rnst1 3302352
#define T2_rnst1 128133
#define T1_cnst 6021207
#define T2_cnst 2071692
#define T1_rnst2 4314078
#define T2_rnst2 115875
*/
/* *10
#define T1_rtt 12281260
#define T2_rtt 2409880
#define T1_rnst1 3669280
#define T2_rnst1 142370
#define T1_cnst 6690230
#define T2_cnst 2301880
#define T1_rnst2 4793420
#define T2_rnst2 128750
*/

/* *6
#define T1_rtt 7368756
#define T2_rtt 1445928
#define T1_rnst1 2201568
#define T2_rnst1 85422
#define T1_cnst 4014138
#define T2_cnst 1381128
#define T1_rnst2 2876052
#define T2_rnst2 77250
*/

/* *7
#define T1_rtt 8596882
#define T2_rtt 1686916
#define T1_rnst1 2568496
#define T2_rnst1 99659
#define T1_cnst 4683161
#define T2_cnst 1611316
#define T1_rnst2 3355394
#define T2_rnst2 90125
*/

// Trial by Ankit
/*mean+2*std-dev X=8
#define T1_rtt 5080646
#define T2_rtt 1918813
#define T1_rnst1 4574751
#define T2_rnst1 1698345
#define T1_cnst 4646422
#define T2_cnst 1743516
#define T1_rnst2 4934728
#define T2_rnst2 1718079
*/

/*X = 2
#define T1_rtt 1320429
#define T2_rtt 743086
#define T1_rnst1 1231791
#define T2_rnst1 718230
#define T1_cnst 851217
#define T2_cnst 699306
#define T1_rnst2 1308216
#define T2_rnst2 701384
*/

/*X = 3
#define T1_rtt 2564670
#define T2_rtt 2250030
#define T1_rnst1 2357181
#define T2_rnst1 234927
#define T1_cnst 4414908
#define T2_cnst 2432598
#define T1_rnst2 5810070
#define T2_rnst2 54675
*/

/*X = 2 L40 P99
#define T1_rtt 1320429
#define T1_rnst1 1231791
#define T1_cnst 851217
#define T1_rnst2 1308216
#define T2_rtt 743086
#define T2_rnst1 718230
#define T2_cnst 699306
#define T2_rnst2 701384
*/

/*X = 2 L40 P99 new 
#define T1_rtt 1691305
#define T1_rnst1 1647280
#define T1_cnst 1291681
#define T1_rnst2 1625737
#define T2_rtt 1117942
#define T2_rnst1 1055081
#define T2_cnst 1112655
#define T2_rnst2 1064107
*/

/*X = 3 L40 P99 new */
#define T1_rtt 2536958
#define T1_rnst1 2470920
#define T1_cnst 1937521
#define T1_rnst2 2438606
#define T2_rtt 1676913
#define T2_rnst1 1582621
#define T2_cnst 1668983
#define T2_rnst2 1668983


/*X = 4 L40 P99
#define T1_rtt 2640859
#define T1_rnst1 2463583
#define T1_cnst 1702434
#define T1_rnst2 2616432
#define T2_rtt 1486173
#define T2_rnst1 1436460
#define T2_cnst 1398613
#define T2_rnst2 1402768
*/
/*X = 5 L40 P99
#define T1_rtt 3301073
#define T2_rtt 1857716
#define T1_rnst1 3079479
#define T2_rnst1 1795575
#define T1_cnst 2128043
#define T2_cnst 1748266
#define T1_rnst2 3270540
#define T2_rnst2 1753460
*/

/*X = 8 L40 P70
#define T1_rtt 1921382
#define T2_rtt 737868
#define T1_rnst1 1705326
#define T2_rnst1 683056
#define T1_cnst 1803165
#define T2_cnst 568294
#define T1_rnst2 1826848
#define T2_rnst2 602693
*/

/*X = 10 L40 P70
#define T1_rtt 2401727
#define T1_rnst1 2131657
#define T1_cnst 2253956
#define T1_rnst2 2283560
#define T2_rtt 922335
#define T2_rnst1 853820
#define T2_cnst 710368
#define T2_rnst2 753366
*/

/* X=12 L40 P70
#define T1_rtt 2882073
#define T2_rtt 1106802
#define T1_rnst1 2557989
#define T2_rnst1 1024584
#define T1_cnst 2704747
#define T2_cnst 852442
#define T1_rnst2 2740272
#define T2_rnst2 904040
*/

/* X=13 L40 P70
#define T1_rtt 3122245
#define T2_rtt 1199035
#define T1_rnst1 2771154
#define T2_rnst1 1109966
#define T1_cnst 2930143
#define T2_cnst 923478
#define T1_rnst2 2968628
#define T2_rnst2 979376
*/

/*X=14 L40 P70
#define T1_rtt 3362418
#define T1_rnst1 2984320
#define T1_cnst 3155538
#define T1_rnst2 3196984
#define T2_rtt 1291269
#define T2_rnst1 1195348
#define T2_cnst 994515
#define T2_rnst2 1054713
*/

/* X=16 L40 P70
#define T1_rtt 3842764
#define T2_rtt 1475736
#define T1_rnst1 3410652
#define T2_rnst1 1366112
#define T1_cnst 3606330
#define T2_cnst 1136589
#define T1_rnst2 3653696
#define T2_rnst2 1205386
*/
/* X=17 L40 P70
#define T1_rtt 4082936
#define T2_rtt 1567969
#define T1_rnst1 3623817
#define T2_rnst1 1451494
#define T1_cnst 3831725
#define T2_cnst 1207626
#define T1_rnst2 3882052
#define T2_rnst2 1280723
*/

/* X=18 L40 P70
#define T1_rtt 4323109
#define T2_rtt 1660203
#define T1_rnst1 3836983
#define T2_rnst1 1536876
#define T1_cnst 4057121
#define T2_cnst 1278663
#define T1_rnst2 4110408
#define T2_rnst2 1356060
*/
/* X=19 L40 P70
#define T1_rtt 4563282
#define T2_rtt 1752436
#define T1_rnst1 4050149
#define T2_rnst1 1622258
#define T1_cnst 4282516
#define T2_cnst 1349699
#define T1_rnst2 4338764
#define T2_rnst2 1431396
*/

/* X=20 L40 P70
#define T1_rtt 4803455
#define T2_rtt 1844670
#define T1_rnst1 4263315
#define T2_rnst1 1707640
#define T1_cnst 4507912
#define T2_cnst 1420736
#define T1_rnst2 4567120
#define T2_rnst2 1506733
*/
/*mean std-dev X=7
#define T1_rtt 3042126
#define T2_rtt 1155645
#define T1_rnst1 2805233
#define T2_rnst1 977725
#define T1_cnst 2564251
#define T2_cnst 1007264
#define T1_rnst2 2953688
#define T2_rnst2 1130730
*/
/*mean std-dev X=8
#define T1_rtt 3476716
#define T2_rtt 1320738
#define T1_rnst1 3205981
#define T2_rnst1 1117401
#define T1_cnst 2930572
#define T2_cnst 1151159
#define T1_rnst2 3375644
#define T2_rnst2 1292263
*/

/*mean+2*std-dev X=2
#define T1_rtt 1270161
#define T1_rnst1 1143687
#define T1_cnst 1161605
#define T1_rnst2 1233682
#define T2_rtt 479703
#define T2_rnst1 424586
#define T2_cnst 435879
#define T2_rnst2 429519
*/

/*mean+2*std-dev X=4
#define T1_rtt 2540323
#define T1_rnst1 2287375
#define T1_cnst 2323211
#define T1_rnst2 2467364
#define T2_rtt 959406
#define T2_rnst1 849172
#define T2_cnst 871758
#define T2_rnst2 859039
*/

/*mean+2*std-dev X=5
#define T1_rtt 3175404
#define T1_rnst1 2859219
#define T1_cnst 2904013
#define T1_rnst2 3084205
#define T2_rtt 1199258
#define T2_rnst1 1061465
#define T2_cnst 1089697
#define T2_rnst2 1073799
*/

/*mean+2*std-dev X=8
#define T1_rtt 5080646
#define T2_rtt 1918813
#define T1_rnst1 4574751
#define T2_rnst1 1698345
#define T1_cnst 4646422
#define T2_cnst 1743516
#define T1_rnst2 4934728
#define T2_rnst2 1718079
*/

#define T_sample_rtt 3510000
#define T_sample_cnst 400000

// #define BPF_MAP_TYPE_RINGBUF 28
#define bpf_tc_printk(fmt, ...)                    \
    ({                                             \
        const char ____fmt[] = fmt;                \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
                         ##__VA_ARGS__);           \
    })

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, skbAddr);
    __type(value, flow_id_tstamp);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} per_flow_inward_RNS_time_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, skbAddr);
    __type(value, flow_id_tstamp);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} per_flow_outward_RNS_time_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, skbAddr);
    __type(value, flow_id_tstamp);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} per_flow_interpod_RNS_time_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, flow_id_seq);
    __type(value, timestamps);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_CNS_rtt_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, flow_def);
    __type(value, flow_def);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pod_IP_to_DC_IP_map SEC(".maps");

struct
{
    //__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, flow_id_seq);
    __type(value, timestamps);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_seq_timestamp_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, flow_def);
    __type(value, flow_report); // avg rtt
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_report_map SEC(".maps");
/*
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key_size, sizeof(int));
    __type(value_size, sizeof(__u32));
    __uint(max_entries, 32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} perf_event_map SEC(".maps");
*/
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    //  __type(key_size, sizeof(int));
    //  __type(value_size, sizeof(__u32));
    __uint(max_entries, 256 * 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ringbuf_map SEC(".maps");

/*
Below section can be hooked to TC ingress of external interface to compute the time spent in root name space
*/
SEC("ext_int_ingress")
int ext_ingress(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    int rc = TC_ACT_OK;
    skbAddr skbuff_addr;
    flow_id_tstamp flow_tstamp;

    skbuff_addr.skb_addr = skb;
    /*  Get Eth header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
    {
        return rc;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        // Non-IP packets, ignore for now
        return rc;
    }

    /* Get IP header */
    struct iphdr *iph = (struct iphdr *)(void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
    {
        return rc;
    }

    if (iph->protocol == IPPROTO_UDP)
    {
        // bpf_tc_printk("\n Ingress UDP packet");
        struct udphdr *udph = (struct udphdr *)(void *)(iph + 1);
        if (udph + 1 > data_end)
        {
            return rc;
        }

        if (udph->dest == bpf_htons(8472)) // flannel packet
        {
            /*
            Get the timestamp and update in the map with sk_buff address as the key.
            Structure flow_id_tstamp track the timestamp. It also comprise flow_id.
            This is not used for inward packets. But is used for outward packets
            to track cluster IP to DC IP mapping. Since it is not used in the inward
            direction, setting the flow_id information to 0.
            */
            flow_tstamp.tstamp = bpf_ktime_get_ns();
            flow_tstamp.id.saddr = 0;
            flow_tstamp.id.daddr = 0;
            flow_tstamp.id.sport = 0;
            flow_tstamp.id.dport = 0;
            flow_tstamp.seqNo_rtt = 0;
            flow_tstamp.seqNo_cnst = 0;
            flow_tstamp.data = 0;
            bpf_map_update_elem(&per_flow_inward_RNS_time_map, &skbuff_addr, &flow_tstamp, BPF_ANY);
            // bpf_tc_printk("Timestamp at tc-ingress: %llu", flow_tstamp.tstamp);
        }
    }
    return TC_ACT_OK;
}

/*
Below section can be hooked to TC egress of external interface to compute the time spent in root name space
*/
SEC("ext_int_egress")
int ext_egress(struct __sk_buff *skb)
{

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    int rc = TC_ACT_OK;
    flow_id_tstamp *flow_tstamp;
    flow_id_seq my_flow_id_seq;

    skbAddr skbuff_addr;
    flow_def pod_flow_id;
    flow_def reverse_flow_id;
    // flow_def dc_flow_id;
    flow_report *report;
    __u64 rnst_da = 0;
    __u64 rnst2 = 0;
    __u64 tstamp = 0;
    __u32 ts = 0;

    skbuff_addr.skb_addr = skb;
    /* Get Eth header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
    {
        return rc;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        // Non-IP packets, ignore for now
        return rc;
    }

    /* Get IP header */
    struct iphdr *iph = (struct iphdr *)(void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
    {
        return rc;
    }
    if (iph->protocol == IPPROTO_UDP)
    {
        // bpf_tc_printk("\n Ingress UDP packet");

        struct udphdr *udph = (struct udphdr *)(void *)(iph + 1);
        if (udph + 1 > data_end)
        {
            return rc;
        }
        if (udph->dest == bpf_htons(8472)) // flannel
        {
            tstamp = bpf_ktime_get_ns();
            /*
            lookup the map based with sk_buff address as key and get the entry inserted at ingress.
            We also use the same map to track the cluster space address to DC space address.
            For outward packet, the cluster space flow_id is added at the veth interface while
            adding the entry to the map. The same is retrieved from map. DC space flow_id is parsed
            and retrieved from the packet. Then both the IPs are updated in pod_IP_to_DC_IP_map map with
            cluster space flow_id (pod IP) as the key.
            */
            flow_tstamp = bpf_map_lookup_elem(&per_flow_outward_RNS_time_map, &skbuff_addr);
            if (flow_tstamp != NULL)
            {
                /*
                get the cluster space flow information from map
                */
                pod_flow_id.saddr = flow_tstamp->id.saddr;
                pod_flow_id.daddr = flow_tstamp->id.daddr;
                pod_flow_id.sport = flow_tstamp->id.sport;
                pod_flow_id.dport = flow_tstamp->id.dport;

                reverse_flow_id.saddr = flow_tstamp->id.daddr;
                reverse_flow_id.daddr = flow_tstamp->id.saddr;
                reverse_flow_id.sport = flow_tstamp->id.dport;
                reverse_flow_id.dport = flow_tstamp->id.sport;

                /*
                get the DC space flow information from the packet

                dc_flow_id.saddr = iph->saddr;
                dc_flow_id.daddr = iph->daddr;
                dc_flow_id.sport = udph->source;
                dc_flow_id.dport = udph->dest;

                add the pod IP to DC network IP mapping in pod_IP_to_DC_IP_map

                bpf_map_update_elem (&pod_IP_to_DC_IP_map, &pod_flow_id, &dc_flow_id, BPF_ANY);
                */
                /*
                time spent at root name space is the difference of timestamp between egress and ingress.
                Lookup the map that store the ingress RNS timestamp. Retrieve the current timestamp and
                then compute the difference between the two.
                */
                ts = (__u32)(tstamp - flow_tstamp->tstamp);
                //                ts = (__u32) (bpf_ktime_get_ns() - flow_tstamp->tstamp);
                if (flow_tstamp->data == 1 || flow_tstamp->data == 3)
                {
                    /* outgoing data packet. Compute RNST_D (ts) and add to seqNo map. Lookup
                    with flow id and seqNo and update RNST_D. */

                    my_flow_id_seq.id = pod_flow_id;
                    my_flow_id_seq.seq = flow_tstamp->seqNo_rtt;
                    timestamps *seq_timestamps = bpf_map_lookup_elem(&flow_seq_timestamp_map, &my_flow_id_seq);
                    if (seq_timestamps != NULL)
                    {
                        seq_timestamps->rnst = ts;
                        bpf_map_update_elem(&flow_seq_timestamp_map, &my_flow_id_seq, seq_timestamps, BPF_EXIST);
                    }

                    /*bpf_tc_printk("Flow Detail at TC-egress for outgoing data packet: %x, %x, %u",
                                  bpf_htonl(pod_flow_id.saddr), bpf_htonl(pod_flow_id.daddr), my_flow_id_seq.seq);
                    bpf_tc_printk("And the RNSTD is: %u", ts);*/
                }
                if (flow_tstamp->data == 0 || flow_tstamp->data == 3)
                {
                    /*
                    Outgoing ack packet. Compute RNST_A, it is the already computed ts. Get RNST_DA from the seqNo map
                     */
                    my_flow_id_seq.id = pod_flow_id;
                    my_flow_id_seq.seq = flow_tstamp->seqNo_cnst;
                    timestamps *seq_timestamps = bpf_map_lookup_elem(&flow_CNS_rtt_map, &my_flow_id_seq);
                    if (seq_timestamps != NULL)
                    {
                        rnst_da = seq_timestamps->rnst;
                        rnst2 = rnst_da + ts;
                        bpf_map_delete_elem(&flow_CNS_rtt_map, &my_flow_id_seq);
                        /*bpf_tc_printk("\n Deleted: %u", my_flow_id_seq.seq);*/

                        /*
                           Add the RNST2 for the flow to the flow_report_map. We maintain RNS time for each
                           flow as a running average. So retrieve the entry for the flow from flow_report_map
                           and then compute the running average if RNST2 time is already presenti, else update the time.
                           We update RNST2 entry only after RTT is updated. So if an entry is not present in flow_report_map,
                           we simply skip.
                         */
                        report = bpf_map_lookup_elem(&flow_report_map, &pod_flow_id);
                        if (report != NULL)
                        {
                            if (report->avg_rnst2 == 0)
                                report->avg_rnst2 = rnst2;
                            else
                                report->avg_rnst2 = rnst2 / 4 + (report->avg_rnst2 * 3) / 4;
                            //                            report->avg_rnst2 = (rnst2*3)/4 + report->avg_rnst2/4;
                            //    report->avg_rnst2 = (rnst2 + report->avg_rnst2) / 2;

                            /*TODO add perfevent here if report->avg_rnst2 > threshold */
                            bpf_map_update_elem(&flow_report_map, &pod_flow_id, report, BPF_EXIST);
                            /*bpf_tc_printk("\n Flow Details of outgoing ack packet: %x, %x, %u",
                                          bpf_htonl(pod_flow_id.saddr), bpf_htonl(pod_flow_id.daddr), my_flow_id_seq.seq);
                            bpf_tc_printk("RNSTA: %u, RNSTDA: %llu, RNST2: %llu", ts, rnst_da, rnst2);
                            bpf_tc_printk("\n Internode RNST2:%u, %u, %llu",
                              my_flow_id_seq.seq,
                              report->avg_rnst2,
                              rnst2);*/
                            if (report->avg_rnst2 > T1_rnst2)
                            {
                                ringbuf_data *data;
                                data = bpf_ringbuf_reserve(&ringbuf_map, sizeof(ringbuf_data), 0);
                                if (data)
                                {
                                    data->saddr = flow_tstamp->id.saddr;
                                    data->daddr = flow_tstamp->id.daddr;
                                    data->sport = flow_tstamp->id.sport;
                                    data->dport = flow_tstamp->id.dport;
                                    data->type = 4;
                                    data->value = rnst2;
                                    data->seqNo = 0;
                                    data->ackNo = flow_tstamp->seqNo_cnst;
                                    //                            bpf_perf_event_output(skb, &perf_event_map, 0, &data, sizeof(data));

                                    // bpf_ringbuf_output(&ringbuf_map, &data, sizeof(data), 0);
                                    bpf_ringbuf_submit(data, 0);
                                }
                            }
                        }
                        //            else
                        //          {
                        //            // bpf_tc_printk("\nreport is NULL");
                        //      }
                    } // seq_tstamp entry is NULL
                    else
                    {
                        // bpf_tc_printk("\nseq_timestamps is NULL");
                    }
                }
                //                else
                //              {
                //                // bpf_tc_printk("\ndata is neither 0 or 1");
                //          }
                /*
                else
                     {
                     my_report.avg_rtt = 0;
                     my_report.avg_rns_time = ts;
                     my_report.avg_cns_time = 0;
                bpf_map_update_elem(&flow_report_map, &pod_flow_id, &my_report, BPF_NOEXIST);
                }
                */
                bpf_map_delete_elem(&per_flow_outward_RNS_time_map, &skbuff_addr);
            }

            /*    else
                  {
                  bpf_tc_printk("\n Ext Egress per_flow_RNS_time_map lookup failed for skb addr %lu", skb);

                  }
             */
        }
    }

    return TC_ACT_OK;
}

/*
Hook below section to pod's veth interface (veth ingress) to compute round trip time,
time spent in root name space and time spent in container name space.
*/
SEC("xflow_rtt_ingress")
int xflow_ingress(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    int rc = TC_ACT_OK;
    timestamps my_seq_timestamps;
    flow_id_seq my_flow_id_seq;
    flow_id_seq cns_flow_id_seq;
    flow_def my_flow_id;
    flow_id_tstamp flow_tstamp;
    flow_report my_report;
    __u64 tstamp;
    skbAddr skbuff_addr;
    unsigned int payload_len = 0;
    __u16 flag = 0xffff;
    ringbuf_data *rb_data = NULL;

    /* Get Eth header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
    {
        return rc;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        // Non-IP packets, ignore for now
        return rc;
    }

    /* Get IP header */
    struct iphdr *iph = (struct iphdr *)(void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
    {
        return rc;
    }

    if (iph->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcph = (struct tcphdr *)(void *)(iph + 1);
        if (tcph + 1 > data_end)
        {
            return rc;
        }
        payload_len = bpf_htons(iph->tot_len) - 4 * (iph->ihl + tcph->doff);

        /*
           To compute the time spent in root name space, track the timestamp at veth ingress.
           This packet could be destined to a pod in another node or within the same node.
           Based on the destination pod's node, we add the timestamp to different map.
           sk_buff address is the key form the map. If the destination pod is in a different pod,
           add the entry to per_flow_outward_RNS_time_map. Entry from this map is further read
           from section "ext_int_egress" and time spent at root name space is computed. We use this
           map to also track cluster space address to DC space address mapping. So cluster space flow
           information is also added to the map in addition to timestamp.
           If the packet is destined to a pod in the same node, then entry is added to
           per_flow_interpod_RNS_time_map.
         */
        skbuff_addr.skb_addr = skb;
        my_flow_id.saddr = iph->saddr;
        my_flow_id.daddr = iph->daddr;
        my_flow_id.sport = tcph->source;
        my_flow_id.dport = tcph->dest;

        tstamp = bpf_ktime_get_ns();
        flow_tstamp.id = my_flow_id;
        flow_tstamp.tstamp = tstamp;
        flow_tstamp.seqNo_rtt = 0;  // initializing
        flow_tstamp.seqNo_cnst = 0; // initializing
        flow_tstamp.data = 10;      // intitalizing to an invalid value
        /* data value of 0 indicates ack, 1 indicates data */

        /*
        set flag to 1 for intra-node flows (packets between pods in the same node).
        set flag to 0 for inter-node flows (packets between pods in different node).
        */
        if (0 == ((bpf_htonl(iph->saddr) & 0xffffff00) ^ (bpf_htonl(iph->daddr) & 0xffffff00)))
            flag = 1;
        else
            flag = 0;
        // monitoring packets across pods
        if ((bpf_htonl(iph->daddr) & 0xffff0000) != 0x0AF40000)
            return rc;
        // dont consider pkts to 10.244.0.0 the flannel vtep interface
        if ((bpf_htonl(iph->daddr) & 0xffffffff) == 0x0AF40000)
            return rc;
        if (flag == 1)
        {
            if (tcph->ack == 1)
            {
                /*
                   Ack packet from veth interface. Compute the CNS time.
                   Retrieve the data packet's timestamp updated in veth egress from flow_CNS_rtt_map.
                   Time difference between the data packet and its ack's gives the time spent in
                   container name space.
                   At veth egress, we need to compute RNSTD, RNSTDA and RNSTA. To differentiate between these
                   three computation, we set the rnst_flag variable inside flow_tstamp structure to 1, 2, 3 for
                   RNSTD, RNSTDA and RNSTA respectively. This is set at veth ingress.
                 */
                cns_flow_id_seq.id = my_flow_id;
                cns_flow_id_seq.seq = bpf_htonl(tcph->ack_seq);
                timestamps *seq_timestamps = bpf_map_lookup_elem(&flow_CNS_rtt_map, &cns_flow_id_seq);
                if (seq_timestamps != NULL)
                {
                    __u32 cns_rtt = (__u32)(tstamp - seq_timestamps->send_tstamp); // skb->tstamp;

                    /*
                       use this sample only if it is not a delayed ack. Considering a delayed ack sample to avg cns inflates the value
                       and further affects the detection and gives rise to false positives. We identify if it is a delayed ack by
                       checking if cns_rtt is greater than the threshold and if the payload lengh is 0. We ignore such samples.
                       This check can lead to missing actual load delayed ack. But we assume that an actual load will cause delay to many
                       packets and thus we will be able to detect it.
                     */

                    //            if (!((cns_rtt > T_sample_cnst) && (payload_len == 0)))
                    //          {

                    flow_tstamp.data = 3;
                    flow_tstamp.seqNo_cnst = cns_flow_id_seq.seq;
                    /*
                       After computing the rtt, delete the entry from map.
                     */
                    //                bpf_map_delete_elem(&flow_CNS_rtt_map, &cns_flow_id_seq);

                    /*
                       Add the CNS time (cns_rtt) for the flow (ACK's flow id is taken here) to the flow_report_map.
                       We maintain CNS time for each flow as a moving average. So retrieve the entry for the flow
                       from flow_report_map and then compute the running average if CNS time is already present,
                       else update the time. We update CNS entry only after RTT is updated. So if an entry is not
                       present in flow_report_map, we simply skip.
                     */
                    flow_report *report = bpf_map_lookup_elem(&flow_report_map, &my_flow_id);
                    __u32 cnst_value = 0;

                    if (report != NULL)
                    {
                        if (report->avg_cnst == 0)
                        {
                            report->avg_cnst = cns_rtt;
                        }
                        else
                        {
                            // report->avg_cnst = (cns_rtt*3)/4 + report->avg_cnst/4;
                            report->avg_cnst = (cns_rtt / 4 + (report->avg_cnst * 3) / 4);
                            // report->avg_cnst = (cns_rtt + report->avg_cnst) / 2;
                        }
                        /*TODO add perfevent here if report->avg_cnst > threshold */
                        bpf_map_update_elem(&flow_report_map, &my_flow_id, report, BPF_EXIST);
                        cnst_value = report->avg_cnst;
                        //                        rb_data.value = cns_rtt;
                    }
                    else
                    {
                        my_report.avg_rtt = 0;
                        my_report.avg_rnst1 = 0;
                        my_report.avg_cnst = cns_rtt;
                        my_report.avg_rnst2 = 0;
                        /*TODO add perfevent here if report->avg_cnst2 > threshold */
                        bpf_map_update_elem(&flow_report_map, &my_flow_id, &my_report, BPF_NOEXIST);
                        cnst_value = cns_rtt;
                        //                      perf_data.value = cns_rtt;
                    }

                    /*bpf_tc_printk("\n Intranode CNST: %u, %u, %u",
                                  bpf_htonl(tcph->ack_seq),
                                  cnst_value,
                                  cns_rtt);*/
                    if (cnst_value > T2_cnst)
                    {
                        // bpf_tc_printk("\n CNST: %x, %x, : %d", bpf_htonl(my_flow_id.saddr), bpf_htonl(my_flow_id.daddr), cnst_value);
                        rb_data = bpf_ringbuf_reserve(&ringbuf_map, sizeof(ringbuf_data), 0);
                        if (rb_data)
                        {
                            rb_data->saddr = my_flow_id.saddr;
                            rb_data->daddr = my_flow_id.daddr;
                            rb_data->sport = my_flow_id.sport;
                            rb_data->dport = my_flow_id.dport;
                            rb_data->type = 3;
                            rb_data->value = cns_rtt;
                            rb_data->seqNo = 0;
                            rb_data->ackNo = bpf_htonl(tcph->ack_seq);
                            // bpf_perf_event_output(skb, &perf_event_map, 0, &perf_data, sizeof(perf_data));
                            bpf_ringbuf_submit(rb_data, 0);
                        }
                    }
                    //              }
                }
            }
            if (payload_len != 0 && payload_len > 20)
            {
                /*
                   Contains data packet. Add the flow to map for RTT computation.
                   Update expected ack number in the seq field.
                 */
                my_flow_id_seq.id = my_flow_id;
                my_flow_id_seq.seq = bpf_htonl(tcph->seq) + payload_len;
                /*
                   if (tcph->syn == 1) //for syn
                   {
                   my_flow_id_seq.seq = bpf_htonl(tcph->seq) + 1;
                   }
                   else //normal data packet
                   {
                   my_flow_id_seq.seq = bpf_htonl(tcph->seq) + payload_len;
                   }*/

                my_seq_timestamps.send_tstamp = tstamp;
                my_seq_timestamps.rnst = 0;
                //                my_seq_timestamps.flag = 0;
                // flow_tstamp.data = 1;
                bpf_map_update_elem(&flow_seq_timestamp_map, &my_flow_id_seq, &my_seq_timestamps, BPF_ANY);
                /* 3 indicates ack, 1 indicates data, 4 indicates both */
                if (flow_tstamp.data == 3)
                    flow_tstamp.data = 4;
                else
                    flow_tstamp.data = 1;
                flow_tstamp.seqNo_rtt = my_flow_id_seq.seq;
            }
        }
        else
        {
            if (tcph->ack == 1)
            {
                /*
                   Ack packet from veth interface. Compute the CNS time.
                   Retrieve the data packet's timestamp updated in veth egress from flow_CNS_rtt_map.
                   Time difference between the data packet and its ack's gives the time spent in
                   container name space.
                 */
                cns_flow_id_seq.id = my_flow_id;
                cns_flow_id_seq.seq = bpf_htonl(tcph->ack_seq);
                timestamps *seq_timestamps = bpf_map_lookup_elem(&flow_CNS_rtt_map, &cns_flow_id_seq);
                //                if (seq_timestamps != NULL && seq_timestamps->flag == 0)    // Added by Ankit
                if (seq_timestamps != NULL)
                {
                    __u32 cns_rtt = (__u32)(tstamp - seq_timestamps->send_tstamp); // skb->tstamp;
                    flow_tstamp.data = 0;
                    flow_tstamp.seqNo_cnst = cns_flow_id_seq.seq;
                    /*
                       After computing the rtt, delete the entry from map.
                     */
                    // bpf_map_delete_elem(&flow_CNS_rtt_map, &cns_flow_id_seq);

                    /*
                       Add the CNS time (cns_rtt) for the flow (ACK's flow id is take here) to the flow_report_map.
                       We maintain CNS time for each flow as a moving average. So retrieve the entry for the flow
                       from flow_report_map and then compute the running average if CNS time is already presenti,
                       else update the time. We update CNS entry only after RTT is updated. So if an entry is not
                       present in flow_report_map, we simply skip.
                     */
                    // if (!((cns_rtt > T_sample_cnst) && (payload_len == 0)))
                    //{
                    __u32 cnst_value = 0;
                    flow_report *report = bpf_map_lookup_elem(&flow_report_map, &my_flow_id);
                    if (report != NULL)
                    {
                        if (report->avg_cnst == 0)
                            report->avg_cnst = cns_rtt;
                        else
                            // report->avg_cnst = (cns_rtt*3)/4 + report->avg_cnst/4;
                            report->avg_cnst = cns_rtt / 4 + (report->avg_cnst * 3) / 4;
                        // report->avg_cnst = (cns_rtt + report->avg_cnst) / 2;

                        /*TODO add perfevent here if report->avg_cnst > threshold */
                        bpf_map_update_elem(&flow_report_map, &my_flow_id, report, BPF_EXIST);
                        cnst_value = report->avg_cnst;
                    }
                    else
                    {
                        my_report.avg_rtt = 0;
                        my_report.avg_rnst1 = 0;
                        my_report.avg_cnst = cns_rtt;
                        my_report.avg_rnst2 = 0;
                        /*TODO add perfevent here if report->avg_cnst2 > threshold */
                        bpf_map_update_elem(&flow_report_map, &my_flow_id, &my_report, BPF_NOEXIST);
                        cnst_value = cns_rtt;
                        //                      perf_data.value = cns_rtt;
                    }

                    /*bpf_printk("\n Reading the map at veth ingress");
                    bpf_tc_printk("\n Flow Detail: Seq: %u, Src address: %x, Dst address: %x",
                            cns_flow_id_seq.seq, bpf_htonl(cns_flow_id_seq.id.saddr), bpf_htonl(cns_flow_id_seq.id.daddr));
                    bpf_tc_printk("\n Current time: %llu, Previous time: %llu",
                                tstamp, seq_timestamps->send_tstamp);

                    bpf_tc_printk("\n CNST: %u, %u, %u",
                                  bpf_htonl(tcph->ack_seq),
                                  cnst_value,
                                  cns_rtt);*/

                    // Added by Ankit - using flag to prevent multiple cnst computation before the map
                    // entry gets deleted after rnst computation
                    //                    seq_timestamps->flag = 1;
                    //                  bpf_map_update_elem(&flow_CNS_rtt_map, &cns_flow_id_seq, seq_timestamps, BPF_EXIST);

                    /*bpf_tc_printk("\n Internode CNST: %u, %u, %u",
                                  bpf_htonl(tcph->ack_seq),
                                  cnst_value,
                                  cns_rtt);*/

                    if (cnst_value > T1_cnst)
                    {
                        rb_data = bpf_ringbuf_reserve(&ringbuf_map, sizeof(ringbuf_data), 0);
                        if (rb_data != NULL)
                        {
                            rb_data->saddr = iph->saddr;
                            rb_data->daddr = iph->daddr;
                            rb_data->sport = tcph->source;
                            rb_data->dport = tcph->dest;
                            rb_data->value = cns_rtt;
                            rb_data->type = 3;
                            rb_data->seqNo = 0;
                            rb_data->ackNo = bpf_htonl(tcph->ack_seq);
                            bpf_ringbuf_submit(rb_data, 0);
                        }
                    }
                    //               }
                }
            }
            if (payload_len != 0 && payload_len > 20) // contains data, add to map for rtt computation
            {
                /*
                   Contains data packet. Add the flow to map for RTT computation.
                   Update expected ack number in the seq field.
                 */
                my_flow_id_seq.id = my_flow_id;
                my_flow_id_seq.seq = bpf_htonl(tcph->seq) + payload_len;
                /*
                   if (tcph->syn == 1) //for syn
                   {
                   my_flow_id_seq.seq = bpf_htonl(tcph->seq) + 1;
                   }
                   else //normal data packet
                   {
                   my_flow_id_seq.seq = bpf_htonl(tcph->seq) + payload_len;
                   }*/

                my_seq_timestamps.send_tstamp = tstamp;
                //            my_seq_timestamps.rtt = 0;
                //                my_seq_timestamps.flag = 0;
                my_seq_timestamps.rnst = 0;
                bpf_map_update_elem(&flow_seq_timestamp_map, &my_flow_id_seq, &my_seq_timestamps, BPF_ANY);
                /*bpf_tc_printk("\n flow_id when data is going: %x, %x, %u",
                              bpf_htonl(my_flow_id_seq.id.saddr), bpf_htonl(my_flow_id_seq.id.daddr), my_flow_id_seq.seq);
                bpf_printk("Tstamp: %llu", tstamp);*/
                /* 0 indicates ack, 1 indicates data, 3 indicates both */
                if (flow_tstamp.data == 0)
                    flow_tstamp.data = 3;
                else
                    flow_tstamp.data = 1;
                flow_tstamp.seqNo_rtt = my_flow_id_seq.seq;
            }
        }

        /*add the RNST info to map */
        // if (0 == ((bpf_htonl(iph->saddr) & 0xffffff00) ^ (bpf_htonl(iph->daddr) & 0xffffff00)))
        if (flag == 1)
        {
            /*
               packet for pod in same node. So add to per_flow_interpod_RNS_time_map
             */

            /*bpf_tc_printk("\n flow & sequence at interpod_rns_map: %x, %x, %u",
                          bpf_htonl(flow_tstamp.id.saddr), bpf_htonl(flow_tstamp.id.daddr), flow_tstamp.seqNo);*/
            bpf_map_update_elem(&per_flow_interpod_RNS_time_map, &skbuff_addr, &flow_tstamp, BPF_ANY);
        }
        else
        {
            /*
               packet for pod in different node. So add to per_flow_outward_RNS_time_map
             */
            /*bpf_tc_printk("\n flow & sequence at outward_rns_map: %x, %x, %u",
                          bpf_htonl(flow_tstamp.id.saddr), bpf_htonl(flow_tstamp.id.daddr), flow_tstamp.seqNo);*/
            bpf_map_update_elem(&per_flow_outward_RNS_time_map, &skbuff_addr, &flow_tstamp, BPF_ANY);
        }
    }
    return rc;
}

/*
Hook below section to pod's veth (egress) interface to compute round trip time,
time spent in root name space and time spent in container name space.
*/
SEC("xflow_rtt_egress")
int xflow_egress(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    int rc = TC_ACT_OK;
    flow_id_seq my_flow_id_seq;
    flow_id_seq cns_flow_id_seq;
    flow_def my_flow_id;
    flow_def my_reverseflow_id;
    flow_report my_report;
    timestamps cns_seq_timestamps;
    unsigned int payload_len;
    flow_id_tstamp *flow_tstamp;
    timestamps *seq_timestamps;
    skbAddr skbuff_addr;
    ringbuf_data *rb_data = NULL;
    __u64 tstamp = 0;
    __u64 rnst_da = 0;
    __u64 rnst1 = 0;
    __u64 rnst2 = 0;
    __u32 rtt_value = 0;
    __u32 rnst1_value = 0;

    // bpf_printk("Hello veth egress");
    /* Get Eth header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
    {
        return rc;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        // Non-IP packets, ignore for now
        return rc;
    }

    /* Get IP header */
    struct iphdr *iph = (struct iphdr *)(void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
    {
        return rc;
    }

    if (iph->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcph = (struct tcphdr *)(void *)(iph + 1);
        if (tcph + 1 > data_end)
        {
            return rc;
        }

        payload_len = bpf_htons(iph->tot_len) - 4 * (iph->ihl + tcph->doff);
        my_flow_id.saddr = iph->daddr;
        my_flow_id.daddr = iph->saddr;
        my_flow_id.sport = tcph->dest;
        my_flow_id.dport = tcph->source;
        my_reverseflow_id.saddr = iph->saddr;
        my_reverseflow_id.daddr = iph->daddr;
        my_reverseflow_id.sport = tcph->source;
        my_reverseflow_id.dport = tcph->dest;

        /*
        Compute the time spent at root NS RNST_DA. Lookup to map based on skb address as key and get the
        entry inserted at ingress. Get the current time stamp and the difference between the current
        timestamp and ingress timestamp gives the elapsed time. Lookup per_flow_interpod_RNS_time_map
        if the source is from a pod in the same node, else lookup per_flow_inward_RNS_time_map
        */

        skbuff_addr.skb_addr = skb;
        tstamp = bpf_ktime_get_ns();
        __u32 flag = 0;
        if (0 == ((bpf_htonl(iph->saddr) & 0xffffff00) ^ (bpf_htonl(iph->daddr) & 0xffffff00)))
        {
            /*
             packet from pod in same node. So lookup from interpod map
             */
            flow_tstamp = bpf_map_lookup_elem(&per_flow_interpod_RNS_time_map, &skbuff_addr);
            flag = 1;
        }
        else
        {
            /*
            packet from pod in different node. So lookup inward map.
            */
            flow_tstamp = bpf_map_lookup_elem(&per_flow_inward_RNS_time_map, &skbuff_addr);
            flag = 0;
        }

        //   if ((bpf_htonl(iph->saddr) & 0xffffffff) == 0x0AF40000)
        //     return rc;
        /*
           Add the RNS time (ts) for the flow to the flow_report_map based on whether it is an incoming ACK packet
           incoming data packet. If it is an ACK packet, then compute RNST1 for the flow using RNST_D (computed at TC egress)
           and RNST_DA. If it is a data packet, store the RNST_DA to seq map. We maintain RNS time for each
           flow as a running average. So retrieve the entry for the flow from flow_report_map
           and then compute the running average if RNS time is already presenti, else update the time.
           We update RNS entry only after RTT is updated. So if an entry is not present in flow_report_map,
           we simply skip.
         */
        flow_report *report = bpf_map_lookup_elem(&flow_report_map, &my_flow_id);
        if (flow_tstamp != NULL)
        {
            // bpf_printk("Hello flow_tstamp not null");
            rnst_da = tstamp - flow_tstamp->tstamp;
            /*    if (flag == 1)
                    bpf_map_delete_elem(&per_flow_interpod_RNS_time_map, &skbuff_addr);
                else
                    bpf_map_delete_elem(&per_flow_inward_RNS_time_map, &skbuff_addr);
                if (report != NULL) {
                    if (report->avg_rns_time == 0)
                        report->avg_rns_time = ts;
                    else
                        report->avg_rns_time = (ts + report->avg_rns_time) / 2;
                }
                else
                {
                    my_report.avg_rtt = 0;
                    my_report.avg_rns_time = ts;
                    my_report.avg_cns_time = 0;
                    //my_report.fct = 0;
                    bpf_map_update_elem(&flow_report_map, &my_flow_id, &my_report, BPF_NOEXIST);
                }*/
        }
        else
        {
            // bpf_printk("Hello returning");
            return rc;
        }

        if (flag == 1)
        {
            // bpf_printk("Hello intra-pod packet");
            if (tcph->ack == 1)
            {
                // contains ack. comput RTT
                my_flow_id_seq.id = my_reverseflow_id;
                my_flow_id_seq.seq = flow_tstamp->seqNo_cnst; // Added by Anks
                /*bpf_tc_printk("\n flow & sequence of my_flow_id at veth egress: %x, %x",
                  bpf_htonl(my_flow_id_seq.id.saddr), bpf_htonl(my_flow_id_seq.id.daddr));
                  bpf_tc_printk("\n flow & sequence of flow_tstamp at veth egress: %x, %x, %u",
                  bpf_ntohl(flow_tstamp->id.saddr), bpf_ntohl(flow_tstamp->id.daddr), flow_tstamp->seqNo);*/

                seq_timestamps = bpf_map_lookup_elem(&flow_CNS_rtt_map, &my_flow_id_seq);
                if (seq_timestamps != NULL)
                {
                    rnst2 = seq_timestamps->rnst + rnst_da;
                    report = bpf_map_lookup_elem(&flow_report_map, &my_reverseflow_id);
                    if (report != NULL)
                    {
                        if (report->avg_rnst2 == 0)
                        {
                            report->avg_rnst2 = rnst2;
                        }
                        else
                        {
                            // report->avg_rnst2 = (rnst2*3)/4 + report->avg_rnst2/4;
                            report->avg_rnst2 = (rnst2 / 4 + (report->avg_rnst2 * 3) / 4);
                            // report->avg_rnst2 = (rnst2 + report->avg_rnst2)/2;
                        }

                        /*TODO add perfevent here if report->avg_rnst2 > threshold */
                        bpf_map_update_elem(&flow_report_map, &my_reverseflow_id, report, BPF_EXIST);
                        bpf_map_delete_elem(&flow_CNS_rtt_map, &my_flow_id_seq);
                        /*bpf_tc_printk("\n Deleted: %u",
                          my_flow_id_seq.seq);*/

                        // rb_data = bpf_ringbuf_reserve(&ringbuf_map, sizeof(ringbuf_data), 0);
                        if (report->avg_rnst2 > T2_rnst2)
                        {
                            // bpf_printk("Hello rnst2");
                            rb_data = bpf_ringbuf_reserve(&ringbuf_map, sizeof(ringbuf_data), 0);
                            if (rb_data != NULL)
                            {
                                rb_data->saddr = my_reverseflow_id.saddr;
                                rb_data->daddr = my_reverseflow_id.daddr;
                                rb_data->sport = my_reverseflow_id.sport;
                                rb_data->dport = my_reverseflow_id.dport;
                                rb_data->value = rnst2;
                                rb_data->type = 4;
                                rb_data->seqNo = 0;
                                rb_data->ackNo = bpf_htonl(tcph->ack_seq);
                                bpf_ringbuf_submit(rb_data, 0);
                            }
                        }
                    }
                }
                my_flow_id_seq.id = my_flow_id;
                my_flow_id_seq.seq = bpf_htonl(tcph->ack_seq);
                seq_timestamps = bpf_map_lookup_elem(&flow_seq_timestamp_map, &my_flow_id_seq);
                if (seq_timestamps != NULL)
                {
                    __u32 rtt = (__u32)(tstamp - seq_timestamps->send_tstamp);
                    rnst1 = seq_timestamps->rnst + rnst_da;
                    report = bpf_map_lookup_elem(&flow_report_map, &my_flow_id); // Added by Ankit
                    bpf_map_delete_elem(&flow_seq_timestamp_map, &my_flow_id_seq);
                    /*
                       ignore the RTT sample if its RTT value is hight and payload lenth is zero. This
                       is done to avoind delayed ack inflating the avg rtt measurement.
                     */
                    // if (!((rtt > T_sample_rtt) && (payload_len == 0)))

                    if (report != NULL)
                    {
                        if (report->avg_rtt == 0)
                        {
                            // bpf_printk("Hello intra-pod packet");
                            report->avg_rtt = rtt;
                        }
                        else
                        {
                            // report->avg_rtt = (rtt*3)/4 + report->avg_rtt/4;
                            report->avg_rtt = (rtt / 4 + (report->avg_rtt * 3) / 4);
                            // report->avg_rtt = (rtt + report->avg_rtt) / 2;
                        }

                        if (report->avg_rnst1 == 0)
                        {
                            report->avg_rnst1 = rnst1;
                        }
                        else
                        {
                            // report->avg_rnst1 = (rnst1*3)/4 + report->avg_rnst1/4;
                            report->avg_rnst1 = (rnst1 / 4 + (report->avg_rnst1 * 3) / 4);
                            // report->avg_rnst1 = (rnst1 + report->avg_rnst1) / 2;
                        }

                        rtt_value = report->avg_rtt;
                        // bpf_printk("RTT value: %d\n", rtt_value);
                        rnst1_value = report->avg_rnst1;
                        /*TODO add perfevent here if report->avg_rnst1 > threshold */
                        bpf_map_update_elem(&flow_report_map, &my_flow_id, report, BPF_EXIST);
                    }
                    else
                    {
                        my_report.avg_rtt = rtt;
                        my_report.avg_rnst1 = rnst1;
                        my_report.avg_cnst = 0;
                        my_report.avg_rnst2 = 0;

                        rtt_value = rtt;
                        rnst1_value = rnst1;
                        /*TODO add perfevent here if report->avg_rtt and rnst1 > threshold */
                        bpf_map_update_elem(&flow_report_map, &my_flow_id, &my_report, BPF_NOEXIST);
                    }

                    /*bpf_tc_printk("\n Intranode RTT: %u, %u, %u",
                      bpf_htonl(tcph->ack_seq),
                      rtt_value,
                      rtt);*/
                    if (rtt_value > T2_rtt)
                    {
                        // bpf_printk("\nInside RTT");
                        rb_data = bpf_ringbuf_reserve(&ringbuf_map, sizeof(ringbuf_data), 0);
                        if (rb_data != NULL)
                        {
                            rb_data->saddr = my_flow_id.saddr;
                            rb_data->daddr = my_flow_id.daddr;
                            rb_data->sport = my_flow_id.sport;
                            rb_data->dport = my_flow_id.dport;
                            rb_data->value = rtt;
                            rb_data->type = 1;
                            rb_data->seqNo = 0;
                            rb_data->ackNo = bpf_htonl(tcph->ack_seq);
                            bpf_ringbuf_submit(rb_data, 0);
                        }
                    }

                    if (rnst1_value > T2_rnst1)
                    {
                        rb_data = bpf_ringbuf_reserve(&ringbuf_map, sizeof(ringbuf_data), 0);
                        if (rb_data != NULL)
                        {
                            rb_data->saddr = my_flow_id.saddr;
                            rb_data->daddr = my_flow_id.daddr;
                            rb_data->sport = my_flow_id.sport;
                            rb_data->dport = my_flow_id.dport;
                            rb_data->value = rnst1;
                            rb_data->type = 2;
                            rb_data->seqNo = 0;
                            rb_data->ackNo = bpf_htonl(tcph->ack_seq);
                            bpf_ringbuf_submit(rb_data, 0);
                        }
                    }
                }
            }
            if (payload_len != 0 && payload_len > 20)
            {

                // if (flow_tstamp->data == 1 || flow_tstamp == 4)
                //{
                my_flow_id_seq.id = my_reverseflow_id;
                my_flow_id_seq.seq = flow_tstamp->seqNo_rtt;
                seq_timestamps = bpf_map_lookup_elem(&flow_seq_timestamp_map, &my_flow_id_seq);
                if (seq_timestamps != NULL)
                {
                    seq_timestamps->rnst = rnst_da;
                }

                //             }
                /*
                   Contains data, container will process and send an ack. If we track the timestamp of this data
                   and its ack, we will get the time consumed at CNS. We also need to track RNST_DA so that RNST2 can
                   be computed when the ack egress TC. We store RNST_DA in the seq map and delete only at TC egress.
                 */

                cns_flow_id_seq.id = my_flow_id;
                cns_flow_id_seq.seq = bpf_htonl(tcph->seq) + payload_len;
                //                cns_flow_id_seq.rnst = rnst_da;
                /*
                   update expected ack in the seq field
                 */

                /*
                   if (tcph->syn == 1)
                   {

                //              if syn packet
                /
                cns_flow_id_seq.seq = bpf_htonl(tcph->seq) + 1;
                }
                else
                {
                //normal data packet
                cns_flow_id_seq.seq = bpf_htonl(tcph->seq) + payload_len;
                }
                 */
                cns_seq_timestamps.send_tstamp = tstamp;
                // cns_seq_timestamps.flag = 0;
                //             cns_seq_timestamps.rtt = 0;
                cns_seq_timestamps.rnst = rnst_da;
                bpf_map_update_elem(&flow_CNS_rtt_map, &cns_flow_id_seq, &cns_seq_timestamps, BPF_NOEXIST);
            }

            bpf_map_delete_elem(&per_flow_interpod_RNS_time_map, &skbuff_addr);
        }
        else
        {
            // bpf_printk("Hello inter-pod packet");
            if (tcph->ack == 1)
            {
                // contains ack. comput RTT

                report = bpf_map_lookup_elem(&flow_report_map, &my_flow_id); // Added by Ankit

                my_flow_id_seq.id = my_flow_id;
                my_flow_id_seq.seq = bpf_htonl(tcph->ack_seq);
                /*bpf_tc_printk("\n ACK: flow & sequence of flow_tstamp at veth egress: %x, %x, %u",
                              bpf_ntohl(my_flow_id_seq.id.saddr), bpf_ntohl(my_flow_id_seq.id.daddr), my_flow_id_seq.seq);*/
                seq_timestamps = bpf_map_lookup_elem(&flow_seq_timestamp_map, &my_flow_id_seq);
                if (seq_timestamps != NULL)
                {
                    /*bpf_tc_printk("\n flow_id when ack comes: %x, %x, %u",
                                  bpf_htonl(my_flow_id_seq.id.saddr), bpf_htonl(my_flow_id_seq.id.daddr), my_flow_id_seq.seq);
                    bpf_printk("Current, previous:  %llu, %llu", tstamp, seq_timestamps->send_tstamp);*/
                    __u32 rtt = (__u32)(tstamp - seq_timestamps->send_tstamp);
                    rnst1 = seq_timestamps->rnst + rnst_da;
                    /*bpf_tc_printk("RNSTD: %llu, RNSTDA: %llu, RNST1: %llu", seq_timestamps->rnst, rnst_da, rnst1);*/
                    bpf_map_delete_elem(&flow_seq_timestamp_map, &my_flow_id_seq);
                    // bpf_tc_printk("\n Deleted: %u", my_flow_id_seq.seq);
                    /*
                    ignore the RTT sample if its RTT value is high and payload lenth is zero. This
                    is done to avoind delayed ack inflating the avg rtt measurement.
                    */
                    // if (!((rtt > T_sample_rtt) && (payload_len == 0)))
                    //{

                    if (report != NULL)
                    {
                        if (report->avg_rtt == 0)
                            report->avg_rtt = rtt;
                        else
                            // report->avg_rtt = (rtt*3)/4 + report->avg_rtt/4;
                            report->avg_rtt = (rtt / 4 + (report->avg_rtt * 3) / 4);
                        // report->avg_rtt = (rtt + report->avg_rtt) / 2;

                        if (report->avg_rnst1 == 0)
                            report->avg_rnst1 = rnst1;
                        else
                            // report->avg_rnst1 = (rnst1*3)/4 + report->avg_rnst1/4;
                            report->avg_rnst1 = (rnst1 / 4 + (report->avg_rnst1 * 3) / 4);
                        // report->avg_rnst1 = (rnst1 + report->avg_rnst1)/2;

                        /*TODO add perfevent here if report->avg_rnst2 > threshold */
                        bpf_map_update_elem(&flow_report_map, &my_flow_id, report, BPF_EXIST);
                        rtt_value = report->avg_rtt;
                        rnst1_value = report->avg_rnst1;
                    }
                    else
                    {
                        my_report.avg_rtt = rtt;
                        my_report.avg_rnst1 = rnst1;
                        my_report.avg_cnst = 0;
                        my_report.avg_rnst2 = 0;
                        /*TODO add perfevent here if report->avg_rnst2 > threshold */
                        bpf_map_update_elem(&flow_report_map, &my_flow_id, &my_report, BPF_NOEXIST);
                        rtt_value = rtt;
                        rnst1_value = rnst1;
                    }
                    //                }
                    /*bpf_tc_printk("\n Internode RTT: %u, %u, %u",
                                  bpf_htonl(tcph->ack_seq),
                                  rtt_value,
                                  rtt);*/
                    if (rtt_value > T1_rtt)
                    {
                        rb_data = bpf_ringbuf_reserve(&ringbuf_map, sizeof(ringbuf_data), 0);
                        if (rb_data != NULL)
                        {
                            rb_data->saddr = my_flow_id.saddr;
                            rb_data->daddr = my_flow_id.daddr;
                            rb_data->sport = my_flow_id.sport;
                            rb_data->dport = my_flow_id.dport;
                            rb_data->value = rtt_value;
                            rb_data->type = 1;
                            rb_data->seqNo = 0;
                            rb_data->ackNo = bpf_htonl(tcph->ack_seq);
                            bpf_ringbuf_submit(rb_data, 0);
                        }
                    }

                    /*bpf_tc_printk("\n Internode RNST1: %u, %u, %u",
                                  bpf_htonl(tcph->ack_seq),
                                  rnst1_value,
                                  rnst1);*/
                    if (rnst1_value > T1_rnst1)
                    {
                        rb_data = bpf_ringbuf_reserve(&ringbuf_map, sizeof(ringbuf_data), 0);
                        if (rb_data != NULL)
                        {
                            rb_data->saddr = my_flow_id.saddr;
                            rb_data->daddr = my_flow_id.daddr;
                            rb_data->sport = my_flow_id.sport;
                            rb_data->dport = my_flow_id.dport;
                            rb_data->value = rnst1;
                            rb_data->type = 2;
                            rb_data->seqNo = 0;
                            rb_data->ackNo = bpf_htonl(tcph->ack_seq);
                            bpf_ringbuf_submit(rb_data, 0);
                        }
                    }
                }
            }

            if (payload_len != 0 && payload_len > 20)
            {
                /*
                   Contains data, container will process and send an ack. If we track the timestamp of this data
                   and its ack, we will get the time consumed at CNS. We also need to track RNST_DA so that RNST2 can
                   be computed when the ack egress TC. We store RNST_DA in the seq map and delete only at TC egress.
                 */

                cns_flow_id_seq.id = my_flow_id;
                cns_flow_id_seq.seq = bpf_htonl(tcph->seq) + payload_len;
                /*
                   update expected ack in the seq field
                 */

                /*
                   if (tcph->syn == 1)
                   {

                //if syn packet
                /
                cns_flow_id_seq.seq = bpf_htonl(tcph->seq) + 1;
                }
                else
                {
                //normal data packet
                cns_flow_id_seq.seq = bpf_htonl(tcph->seq) + payload_len;
                }
                 */
                cns_seq_timestamps.send_tstamp = tstamp;
                // cns_seq_timestamps.rtt = 0;
                cns_seq_timestamps.rnst = rnst_da;
                //                cns_seq_timestamps.flag = 0;    // Added by Ankit

                /*bpf_printk("\n Updating the map at veth egress");
                bpf_tc_printk("\n Flow Detail: Seq: %u, Src address: %x, Dst address: %x",
                            cns_flow_id_seq.seq, bpf_htonl(cns_flow_id_seq.id.saddr), bpf_htonl(cns_flow_id_seq.id.daddr));
                bpf_tc_printk("\n Time Detail: Sequence: %u, timestamp: %llu",
                            cns_flow_id_seq.seq, tstamp);*/

                /*timestamps *seq_timestamps = bpf_map_lookup_elem(&flow_CNS_rtt_map, &cns_flow_id_seq);
                if(seq_timestamps == NULL){
                    bpf_map_update_elem(&flow_CNS_rtt_map, &cns_flow_id_seq, &cns_seq_timestamps, BPF_ANY);
                }
                else{
                    bpf_tc_printk("\n Entry found, Sequence: %u, timestamp at veth egress: %llu",
                            cns_flow_id_seq.seq, tstamp);
                }*/

                bpf_map_update_elem(&flow_CNS_rtt_map, &cns_flow_id_seq, &cns_seq_timestamps, BPF_NOEXIST);
            }
            bpf_map_delete_elem(&per_flow_inward_RNS_time_map, &skbuff_addr);
        }
    }
    return rc;
}
char _license[] SEC("license") = "GPL";
