/*
 ** Copyright (C) 2015-2015 Hogzilla <dev@ids-hogzilla.org>
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License Version 2 as
 ** published by the Free Software Foundation.  You may not use, modify or
 ** distribute this program under any other version of the GNU General
 ** Public License.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software
 ** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 **
 ** This file uses ndpiReader code from lib nDPI
 ** <https://github.com/ntop/nDPI>
 */

/* $Id$ */

/* spo_hogzilla
 * 
 * Purpose:
 *
 *
 * This plugin generates 
 *
 * Arguments:
 *   
 * filename of the output log (default: snort.log)
 *
 * Effect:
 *
 * Packet logs are written to ...
 * file
 *
 * Comments:
 *
 * First logger...
 *
 */


#define HOGZILLA_MAX_NDPI_FLOWS         500000
#define HOGZILLA_MAX_NDPI_PKT_PER_FLOW  200
#define HOGZILLA_MAX_IDLE_TIME          600000 /* 1000=1sec */
//#define IDLE_SCAN_PERIOD                1000   /* 1000=1sec */
#define IDLE_SCAN_PERIOD                10     /* 1000=1sec, 10 is set on original */
#define NUM_ROOTS                       512
#define MAX_EXTRA_PACKETS_TO_CHECK      7
#define TICK_RESOLUTION                 1000
#define GTP_U_V1_PORT                   2152
#define IDLE_SCAN_BUDGET                4096
#define DNS_FLAGS_MASK                  0x8000
#define MAX_CONTACTS                    50
#define CONTACT_NEGLIGIBLE_PAYLOAD      10 /* bytes */
#define CONTACT_MIN_INTERTIME           1000 /* 1seconds */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include <sys/types.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include "decode.h"
#include "mstring.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "util.h"
#include "map.h"
#include "unified2.h"
#include "barnyard2.h"

#include <sched.h>
#include <stdio.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <search.h>
#include <signal.h>
#include <sys/time.h>
#include <inttypes.h>
#include "ndpi_api.h"
#include <sys/socket.h>

#include <glib-object.h>

// Install Thrift with c_glib support
#include <thrift/c_glib/thrift.h>
#include <thrift/c_glib/protocol/thrift_binary_protocol.h>
#include <thrift/c_glib/transport/thrift_buffered_transport.h>
#include <thrift/c_glib/transport/thrift_socket.h>

#include "output-plugins/hogzilla/hbase_types.h"
#include "output-plugins/hogzilla/hbase.h"


typedef struct _HogzillaHBase {
    ThriftSocket          *socket;
    ThriftTransport       *transport;
    ThriftProtocol        *protocol;
    HbaseIf               *client;
    GError                *error;
    IOError               *ioerror;
    IllegalArgument       *iargument;
} HogzillaHBase;

typedef struct _HogzillaData {
    char                *hbase_host;
    u_int32_t           hbase_port;
    time_t              lastTime;
} HogzillaData;

typedef struct reader_hogzilla {
    struct ndpi_detection_module_struct *ndpi_struct;
    void *ndpi_flows_root[NUM_ROOTS];
    u_int64_t last_time;
    u_int64_t last_idle_scan_time;
    u_int32_t idle_scan_idx;
    u_int32_t num_idle_flows;
    u_int32_t ndpi_flow_count;
    //void *eventById[HOGZILLA_MAX_EVENT_TABLE];
    struct ndpi_flow_info *idle_flows[IDLE_SCAN_BUDGET];
} reader_hogzilla;

typedef struct {
  uint8_t kind;
  uint8_t size;
} tcp_option_t;


// flow tracking
typedef struct ndpi_flow_info {
    /* control or not useful vars */
    u_int32_t hashval;
    u_int8_t ip_version;
    u_int8_t in_idle;
    u_int8_t saved;
    u_int8_t  detection_completed,  check_extra_packets;
    u_int8_t fin_stage; /*1: 1st FIN, 2: FIN reply */
    u_int16_t vlan_id;
    void *src_id, *dst_id;
    u_int64_t request_abs_time; /* timestamp used to compute response time for services */
    u_int64_t C_last_time; /* timestamp a contact was noticed */
    u_int64_t first_seen;
    u_int64_t last_seen;

//    Not using for now!
//    /* context and specific information */
//    char bittorent_hash[41];
//    char info[96];
//    char host_server_name[192];
//    struct {
//      char client_info[48], server_info[48];
//    } ssh_ssl;

    /* basic vars */
    u_int32_t src_ip;
    u_int32_t dst_ip;
    u_int16_t src_port;
    u_int16_t dst_port;
    ndpi_protocol detected_protocol;
    u_int8_t  protocol, bidirectional;
    struct ndpi_flow_struct *ndpi_flow;
    char src_name[32], dst_name[32];
    u_int64_t bytes;
    u_int32_t packets;
    u_int64_t payload_bytes;
    u_int32_t packets_without_payload;
    u_int32_t payload_bytes_first;

    /*
     * more packets statistics
     */
    u_int64_t flow_duration;
    u_int64_t src2dst_pay_bytes;
    u_int64_t dst2src_pay_bytes;
    u_int64_t src2dst_header_bytes;
    u_int64_t dst2src_header_bytes;
    u_int32_t src2dst_packets;
    u_int32_t dst2src_packets;

    u_int64_t arrival_time[HOGZILLA_MAX_NDPI_PKT_PER_FLOW];
    u_int8_t  direction[HOGZILLA_MAX_NDPI_PKT_PER_FLOW];
    u_int64_t inter_time[HOGZILLA_MAX_NDPI_PKT_PER_FLOW];
    u_int64_t packet_pay_size[HOGZILLA_MAX_NDPI_PKT_PER_FLOW];
    u_int64_t packet_header_size[HOGZILLA_MAX_NDPI_PKT_PER_FLOW];

    u_int64_t src2dst_inter_time_avg;
    u_int64_t src2dst_inter_time_min;
    u_int64_t src2dst_inter_time_max;
    u_int64_t src2dst_inter_time_std;
    u_int64_t dst2src_inter_time_avg;
    u_int64_t dst2src_inter_time_min;
    u_int64_t dst2src_inter_time_max;
    u_int64_t dst2src_inter_time_std;

    u_int64_t src2dst_pay_bytes_avg;
    u_int64_t src2dst_pay_bytes_min;
    u_int64_t src2dst_pay_bytes_max;
    u_int64_t src2dst_pay_bytes_std;
    u_int64_t dst2src_pay_bytes_avg;
    u_int64_t dst2src_pay_bytes_min;
    u_int64_t dst2src_pay_bytes_max;
    u_int64_t dst2src_pay_bytes_std;

    u_int64_t dst2src_pay_bytes_rate; /*bytes per second */
    u_int64_t src2dst_pay_bytes_rate; /*bytes per second */
    u_int64_t dst2src_packets_rate;   /*packets per second */
    u_int64_t src2dst_packets_rate;   /*packets per second */

    u_int64_t inter_time_avg;
    u_int64_t inter_time_min;
    u_int64_t inter_time_max;
    u_int64_t inter_time_std;

    u_int64_t payload_bytes_avg;
    u_int64_t payload_bytes_std;
    u_int64_t payload_bytes_min;
    u_int64_t payload_bytes_max;

    u_int64_t src2dst_header_bytes_avg;
    u_int64_t src2dst_header_bytes_min;
    u_int64_t src2dst_header_bytes_max;
    u_int64_t src2dst_header_bytes_std;
    u_int64_t dst2src_header_bytes_avg;
    u_int64_t dst2src_header_bytes_min;
    u_int64_t dst2src_header_bytes_max;
    u_int64_t dst2src_header_bytes_std;

    /* TCP exclusive features (counting vars) */
    u_int32_t packets_syn;
    u_int32_t packets_ack;
    u_int32_t packets_fin;
    u_int32_t packets_rst;
    u_int32_t packets_psh;
    u_int32_t packets_urg;
    u_int32_t tcp_retransmissions;

    /* variation estimation */
    u_int32_t payload_size_variation;
    u_int32_t payload_size_variation_expected;

    /*
     * Contacts during connections
     */
    u_int32_t C_number_of_contacts;
    u_int64_t C_src2dst_pay_bytes[MAX_CONTACTS];
    u_int64_t C_dst2src_pay_bytes[MAX_CONTACTS];
    u_int64_t C_src2dst_header_bytes[MAX_CONTACTS];
    u_int64_t C_dst2src_header_bytes[MAX_CONTACTS];
    u_int64_t C_src2dst_packets[MAX_CONTACTS];
    u_int64_t C_dst2src_packets[MAX_CONTACTS];
    u_int64_t C_dst2src_pay_bytes_rate[MAX_CONTACTS];
    u_int64_t C_src2dst_pay_bytes_rate[MAX_CONTACTS];
    u_int64_t C_dst2src_packets_rate[MAX_CONTACTS];
    u_int64_t C_src2dst_packets_rate[MAX_CONTACTS];
    u_int64_t C_start_time[MAX_CONTACTS];
    u_int64_t C_inter_start_time[MAX_CONTACTS];
    u_int64_t C_duration[MAX_CONTACTS];
    u_int64_t C_idletime[MAX_CONTACTS]; /*idle time after ith contact*/
    u_int64_t C_packets_syn[MAX_CONTACTS];
    u_int64_t C_packets_ack[MAX_CONTACTS];
    u_int64_t C_packets_fin[MAX_CONTACTS];
    u_int64_t C_packets_rst[MAX_CONTACTS];
    u_int64_t C_packets_psh[MAX_CONTACTS];
    u_int64_t C_packets_urg[MAX_CONTACTS];
    u_int64_t C_tcp_retransmissions[MAX_CONTACTS];

    u_int64_t C_src2dst_pay_bytes_avg;
    u_int64_t C_src2dst_pay_bytes_min;
    u_int64_t C_src2dst_pay_bytes_max;
    u_int64_t C_src2dst_pay_bytes_std;
    u_int64_t C_src2dst_header_bytes_avg;
    u_int64_t C_src2dst_header_bytes_min;
    u_int64_t C_src2dst_header_bytes_max;
    u_int64_t C_src2dst_header_bytes_std;
    u_int64_t C_src2dst_packets_avg;
    u_int64_t C_src2dst_packets_min;
    u_int64_t C_src2dst_packets_max;
    u_int64_t C_src2dst_packets_std;
    u_int64_t C_dst2src_pay_bytes_avg;
    u_int64_t C_dst2src_pay_bytes_min;
    u_int64_t C_dst2src_pay_bytes_max;
    u_int64_t C_dst2src_pay_bytes_std;
    u_int64_t C_dst2src_header_bytes_avg;
    u_int64_t C_dst2src_header_bytes_min;
    u_int64_t C_dst2src_header_bytes_max;
    u_int64_t C_dst2src_header_bytes_std;
    u_int64_t C_dst2src_packets_avg;
    u_int64_t C_dst2src_packets_min;
    u_int64_t C_dst2src_packets_max;
    u_int64_t C_dst2src_packets_std;
    u_int64_t C_packets_syn_avg;
    u_int64_t C_packets_syn_min;
    u_int64_t C_packets_syn_max;
    u_int64_t C_packets_syn_std;
    u_int64_t C_packets_ack_avg;
    u_int64_t C_packets_ack_min;
    u_int64_t C_packets_ack_max;
    u_int64_t C_packets_ack_std;
    u_int64_t C_packets_fin_avg;
    u_int64_t C_packets_fin_min;
    u_int64_t C_packets_fin_max;
    u_int64_t C_packets_fin_std;
    u_int64_t C_packets_rst_avg;
    u_int64_t C_packets_rst_min;
    u_int64_t C_packets_rst_max;
    u_int64_t C_packets_rst_std;
    u_int64_t C_packets_psh_avg;
    u_int64_t C_packets_psh_min;
    u_int64_t C_packets_psh_max;
    u_int64_t C_packets_psh_std;
    u_int64_t C_packets_urg_avg;
    u_int64_t C_packets_urg_min;
    u_int64_t C_packets_urg_max;
    u_int64_t C_packets_urg_std;
    u_int64_t C_tcp_retransmissions_avg;
    u_int64_t C_tcp_retransmissions_min;
    u_int64_t C_tcp_retransmissions_max;
    u_int64_t C_tcp_retransmissions_std;
    u_int64_t C_dst2src_pay_bytes_rate_avg;
    u_int64_t C_dst2src_pay_bytes_rate_min;
    u_int64_t C_dst2src_pay_bytes_rate_max;
    u_int64_t C_dst2src_pay_bytes_rate_std;
    u_int64_t C_src2dst_pay_bytes_rate_avg;
    u_int64_t C_src2dst_pay_bytes_rate_min;
    u_int64_t C_src2dst_pay_bytes_rate_max;
    u_int64_t C_src2dst_pay_bytes_rate_std;
    u_int64_t C_dst2src_packets_rate_avg;
    u_int64_t C_dst2src_packets_rate_min;
    u_int64_t C_dst2src_packets_rate_max;
    u_int64_t C_dst2src_packets_rate_std;
    u_int64_t C_src2dst_packets_rate_avg;
    u_int64_t C_src2dst_packets_rate_min;
    u_int64_t C_src2dst_packets_rate_max;
    u_int64_t C_src2dst_packets_rate_std;
    u_int64_t C_duration_avg;
    u_int64_t C_duration_min;
    u_int64_t C_duration_max;
    u_int64_t C_duration_std;
    u_int64_t C_idletime_avg;
    u_int64_t C_idletime_min;
    u_int64_t C_idletime_max;
    u_int64_t C_idletime_std;
    u_int64_t C_inter_start_time_avg;
    u_int64_t C_inter_start_time_min;
    u_int64_t C_inter_start_time_max;
    u_int64_t C_inter_start_time_std;

    u_int64_t flow_use_time;
    u_int64_t flow_idle_time;



    /*
     * packets statistics
     */
    /* Request and responses times for HTTP and DNS */
    u_int32_t response_rel_time; /* delta t between request and response */

   /* label information, from misuse IDS */
    Unified2EventCommon *event;


} ndpi_flow_t;

/* list of function prototypes for this output plugin */
static void HogzillaInit(char *);
static HogzillaData *ParseHogzillaArgs(char *);
static void Hogzilla(Packet *, void *, uint32_t, void *);
static void SpoHogzillaCleanExitFunc(int, void *);
static void SpoHogzillaRestartFunc(int, void *);
static struct ndpi_flow_info *packet_processing( const u_int64_t time, u_int16_t vlan_id, const struct ndpi_iphdr *iph, struct ndpi_ipv6hdr *iph6, u_int16_t ip_offset, u_int16_t ipsize, u_int16_t rawsize);
static struct ndpi_flow_info *packet_processing_by_pcap(const struct pcap_pkthdr *header, const u_char *packet);
struct HogzillaHBase *connectHBase();
static void closeHBase();
static void printFlow(struct ndpi_flow_info *);
static void node_idle_scan_walker(const void *, ndpi_VISIT , int , void *);
int node_cmp(const void *, const void *);
static void free_ndpi_flow(struct ndpi_flow_info *);




/* If you need to instantiate the plugin's data structure, do it here */
HogzillaData *hogzilla_ptr;
HogzillaHBase *hbase;
struct reader_hogzilla ndpi_info;

static u_int8_t undetected_flows_deleted = 0;
static u_int16_t decode_tunnels = 0;
#define SIZEOF_ID_STRUCT (sizeof(struct ndpi_id_struct))
#define SIZEOF_FLOW_STRUCT (sizeof(struct ndpi_flow_struct))

GHashTable * attributes;
Text * table ;


void *HzAlloc(size_t size) {
    void *mem = SnortAlloc(size);
    return mem;
}

/*
 * Function: HogzillaSetup()
 *
 * Purpose: Registers the output plugin keyword and initialization 
 *          function into the output plugin list.  This is the function that
 *          gets called from InitOutputPlugins() in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void HogzillaSetup(void) {
    NDPI_PROTOCOL_BITMASK all;
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterOutputPlugin("hogzilla", OUTPUT_TYPE_FLAG__LOG, HogzillaInit);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Output plugin: Hogzilla is setup...\n"););

    memset(&ndpi_info, 0, sizeof(ndpi_info));
    ndpi_info.ndpi_struct = ndpi_init_detection_module();

    if(ndpi_info.ndpi_struct == NULL)
        printf("ERROR: global structure initialization failed\n");

    // enable all protocols
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_info.ndpi_struct, &all);

    (ndpi_info.ndpi_struct)->http_dont_dissect_response = 0;

    //size_id_struct   = ndpi_detection_get_sizeof_ndpi_id_struct();
    //size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();
    //LogMessage("DEBUG => [Hogzilla] Line %d in file %s\n", __LINE__, __FILE__);
}

void signal_callback_handler(int signum){
        printf("Caught signal SIGPIPE %d\n",signum);
}

gboolean thrift_socket_is_open (ThriftSocket *socket) {
  return socket->sd != THRIFT_INVALID_SOCKET;
}

void check_hbase_open(){
    //while(!thrift_transport_is_open (hbase->transport)){
    while(!thrift_socket_is_open (hbase->socket)){
        closeHBase();
        connectHBase();
    }
}

void scan_idle_flows(){

    struct ndpi_flow_info *flow;

    if(ndpi_info.last_idle_scan_time + IDLE_SCAN_PERIOD < ndpi_info.last_time) {
            /* scan for idle flows */
            ndpi_twalk(ndpi_info.ndpi_flows_root[ndpi_info.idle_scan_idx], node_idle_scan_walker,NULL);

            // TODO:  DEBUG
            //HogzillaSaveFlows();

            /* remove idle flows (unfortunately we cannot do this inline) */
            while (ndpi_info.num_idle_flows > 0){
                ndpi_tdelete(ndpi_info.idle_flows[--ndpi_info.num_idle_flows], &ndpi_info.ndpi_flows_root[ndpi_info.idle_scan_idx], node_cmp);
                if(ndpi_info.idle_flows[ndpi_info.num_idle_flows]!=NULL){

                    flow = ndpi_info.idle_flows[ndpi_info.num_idle_flows];
                    if(flow && flow->in_idle==1) {
                        free_ndpi_flow(flow);
                        free(flow);
                    }
                    ndpi_info.idle_flows[ndpi_info.num_idle_flows]=NULL;
                    flow=NULL;
                    ndpi_info.ndpi_flow_count--;
                }
            }
            // LogMessage("DEBUG => [Hogzilla] Flows in memory: %d \n", ndpi_info.ndpi_flow_count);
            if(++ndpi_info.idle_scan_idx == NUM_ROOTS) ndpi_info.idle_scan_idx = 0;
            ndpi_info.last_idle_scan_time = ndpi_info.last_time;
     }
}
/*
void my_alarms(int sig) {
    scan_idle_flows();
    signal(SIGALRM, my_alarms); alarm(ALARMS_RUN);
}*/


/*
 * Function: HogzillaInit(char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
static void HogzillaInit(char *args) {
    int i;
    HogzillaData *data;
    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Output: Hogzilla Initialized\n"););

    /* parse the argument list from the rules file */
    data = ParseHogzillaArgs(args);
    hogzilla_ptr = data;

    attributes = g_hash_table_new(g_str_hash, g_str_equal);
    table = g_byte_array_new ();
    g_byte_array_append (table, (guint*) "hogzilla_flows", 14);

    //AddFuncToPostConfigList(HogzillaInitLogFileFinalize, data);
    //DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Linking Hogzilla functions to call lists...\n"););

    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(Hogzilla, OUTPUT_TYPE__LOG, data);
    AddFuncToCleanExitList(SpoHogzillaCleanExitFunc, data);
    AddFuncToRestartList(SpoHogzillaRestartFunc, data);

    signal(SIGPIPE, signal_callback_handler);
    /* Start timers using ALARMS: Is not running! :( */
    //signal(SIGALRM, my_alarms);  alarm(ALARMS_RUN);

    for(i=0; i< IDLE_SCAN_BUDGET ;i++)
        ndpi_info.idle_flows[i]=NULL;

}

/*
 * Function: ParseHogzillaArgs(char *)
 *
 * Purpose: Process positional args, if any.  Syntax is:
 * output log_tcpdump: [<logpath> [<limit>]]
 * limit ::= <number>('G'|'M'|K')
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 */
static HogzillaData *ParseHogzillaArgs(char *args) {
    char **toks;
    int num_toks;
    HogzillaData *data;
    int i;
    char *hbase_string;
    char *tok;
    const char delimiters[] = ":";  

    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "ParseHogzillaArgs: %s\n", args););
    data = (HogzillaData *) HzAlloc(sizeof(HogzillaData));

    if ( data == NULL )
        FatalError("hogzilla: unable to allocate memory!\n");

    data->hbase_host = "localhost";
    data->hbase_port = 9090;

    if ( args == NULL )
        args = "";

    toks = mSplit((char*)args, " \t", 0, &num_toks, '\\');

    for (i = 0; i < num_toks; i++)
    {
        tok = toks[i];
        switch (i)
        {
        case 0:
            hbase_string = strtok(tok,delimiters);
            data->hbase_host = SnortStrdup(hbase_string);
            hbase_string = strtok(NULL,delimiters);
            if(hbase_string!=NULL)
                data->hbase_port = atoi(hbase_string);

            break;

        case 1:
            break;
        }
    }
    mSplitFree(&toks, num_toks);
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "hogzilla should save on host %s port %ld\n", data->hbase_host, data->hbase_port););
    return data;
}

/*
 * Function: SpoHogzillaCleanExitFunc()
 *
 * Purpose: Cleanup at exit time
 *
 * Arguments: signal => signal that caused this event
 *            arg => data ptr to reference this plugin's data
 *
 * Returns: void function
 */
static void SpoHogzillaCleanup(int signal, void *arg, const char* msg) {
    HogzillaData *data = (HogzillaData *) arg;
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"%s\n", msg););
    closeHBase();
    free(data);
}

static void SpoHogzillaCleanExitFunc(int signal, void *arg) {
    SpoHogzillaCleanup(signal, arg, "SpoHogzillaCleanExitFunc");
}

static void SpoHogzillaRestartFunc(int signal, void *arg) {
    SpoHogzillaCleanup(signal, arg, "SpoHogzillaRestartFunc");
}



static char* ipProto2Name(u_int16_t proto_id) {
    static char proto[8];
    switch(proto_id) {
    case IPPROTO_TCP:
        return("TCP");
        break;
    case IPPROTO_UDP:
        return("UDP");
        break;
    case IPPROTO_ICMP:
        return("ICMP");
        break;
    case IPPROTO_ICMPV6:
        return("ICMPV6");
        break;
    case 112:
        return("VRRP");
        break;
    case IPPROTO_IGMP:
        return("IGMP");
        break;
    }
    snprintf(proto, sizeof(proto), "%u", proto_id);
    return(proto);
}

/* ***************************************************** */
static u_int16_t node_guess_undetected_protocol(struct ndpi_flow_info *flow) {
    flow->detected_protocol = ndpi_guess_undetected_protocol(ndpi_info.ndpi_struct,
            flow->protocol,
            ntohl(flow->src_ip),
            ntohs(flow->src_port),
            ntohl(flow->dst_ip),
            ntohs(flow->dst_port));
    // printf("Guess state: %u\n", flow->detected_protocol);
    return(flow->detected_protocol.master_protocol);
}
/* ***************************************************** */
static void node_proto_guess_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
    struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;

#if 0
    printf("<%d>Walk on node %s (%p)\n",
            depth,
            which == preorder?"preorder":
                    which == postorder?"postorder":
                            which == endorder?"endorder":
                                    which == leaf?"leaf": "unknown",
                                            flow);
#endif

    if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
        if(flow->detected_protocol.master_protocol == NDPI_PROTOCOL_UNKNOWN) {
            node_guess_undetected_protocol(flow);
        }

    }
}
/* ***************************************************** */
static void free_ndpi_flow(struct ndpi_flow_info *flow) {
    if(flow->ndpi_flow) { ndpi_free_flow(flow->ndpi_flow); flow->ndpi_flow = NULL; }
    if(flow->src_id)    { ndpi_free(flow->src_id); flow->src_id = NULL;       }
    if(flow->dst_id)    { ndpi_free(flow->dst_id); flow->dst_id = NULL;       }
    if(flow->event)     { free(flow->event); flow->event = NULL;       }

}
/* ***************************************************** */
void cleanMutation(gpointer data, gpointer b) {
    Mutation *mutation = (Mutation *) data;
    g_byte_array_free(mutation->column,TRUE);
    mutation->column=NULL;
    g_byte_array_free(mutation->value,TRUE);
    mutation->value=NULL;
    g_object_unref (data);
    data = NULL;
    mutation = NULL;
}
/* ***************************************************** */
void cleanBatchMutation(gpointer data, gpointer b) {
    BatchMutation *bm = (BatchMutation *) data;
    g_byte_array_free(bm->row,TRUE);
    bm->row=NULL;
    g_ptr_array_foreach(bm->mutations,cleanMutation,(gpointer) NULL);
    g_ptr_array_free(bm->mutations,TRUE);
    g_object_unref (bm);
    bm->mutations=NULL;
    bm = NULL;
    data = NULL;
}
/* ***************************************************** */
void HogzillaSaveFlows() {
    char str[100];  int i;
    struct ndpi_flow_info *flow;
    hbase = connectHBase();
    GPtrArray * batchRows;
    batchRows = g_ptr_array_new ();

    for(i=0; i< ndpi_info.num_idle_flows ;i++) {
        flow = ndpi_info.idle_flows[i];

        //printf("############# Saving one flow (%d)...\n",i);
        //HogzillaSaveFlow(flow);
        //continue;

        if(flow->saved == 0) {
            BatchMutation *rowMutation;
            rowMutation = g_object_new (TYPE_BATCH_MUTATION, NULL);

            rowMutation->row = g_byte_array_new ();
            snprintf(str,100, "%lld.%lld", flow->first_seen,flow->src_ip) ;
            g_byte_array_append (rowMutation->row,(guint*) str,  strlen(str));

            rowMutation->mutations  = g_ptr_array_new ();
            Hogzilla_mutations(flow,rowMutation->mutations);

            g_ptr_array_add (batchRows, rowMutation);
            rowMutation = NULL;
            flow->saved = 1;

            //printFlow(flow);
        }

    }
    //return;

    //closeHBase();
    //hbase = connectHBase();
    check_hbase_open();

    while(!hbase_client_mutate_rows (hbase->client, table, batchRows ,attributes, &hbase->ioerror, &hbase->iargument, &hbase->error)) {
        if(hbase->error!=NULL)
            LogMessage ("%s\n", hbase->error->message);
        if(hbase->ioerror!=NULL)
            LogMessage ("%s\n", hbase->ioerror->message);
        if(hbase->iargument!=NULL)
            LogMessage ("%s\n", hbase->iargument->message);

        LogMessage("DEBUG => [Hogzilla] Error saving the flow below. Reconnecting and trying again in 10 seconds...\n");
        closeHBase();
        sleep(5);
        hbase = connectHBase();
        sleep(5);
    }

    g_ptr_array_foreach(batchRows,cleanBatchMutation,(gpointer) NULL);
    g_ptr_array_free(batchRows,TRUE);
}
/* ***************************************************** */

static void printFlow(struct ndpi_flow_info *flow) {

  FILE *out = stdout;


  if(true) {

    fprintf(out, "\t%s ", ipProto2Name(flow->protocol));

    fprintf(out, "%s%s%s:%u %s %s%s%s:%u ",
        (flow->ip_version == 6) ? "[" : "",
        flow->src_name, (flow->ip_version == 6) ? "]" : "", ntohs(flow->src_port),
        flow->bidirectional ? "<->" : "->",
        (flow->ip_version == 6) ? "[" : "",
        flow->dst_name, (flow->ip_version == 6) ? "]" : "", ntohs(flow->dst_port)
        );

    if(flow->vlan_id > 0) fprintf(out, "[VLAN: %u]", flow->vlan_id);

    if(flow->detected_protocol.master_protocol) {
      char buf[64];

      fprintf(out, "[proto: %u.%u/%s]",
          flow->detected_protocol.master_protocol, flow->detected_protocol.app_protocol,
          ndpi_protocol2name(ndpi_info.ndpi_struct,
                 flow->detected_protocol, buf, sizeof(buf)));
    } else
      fprintf(out, "[proto: %u/%s]",
          flow->detected_protocol.app_protocol,
          ndpi_get_proto_name(ndpi_info.ndpi_struct, flow->detected_protocol.app_protocol));

    fprintf(out, "[%u pkts/%llu bytes ", flow->src2dst_packets, (long long unsigned int) flow->src2dst_pay_bytes);
    fprintf(out, "%s %u pkts/%llu bytes]",
        (flow->dst2src_packets > 0) ? "<->" : "->",
        flow->dst2src_packets, (long long unsigned int) flow->dst2src_pay_bytes);

//    Not using for now
//    if(flow->host_server_name[0] != '\0') fprintf(out, "[Host: %s]", flow->host_server_name);
//    if(flow->info[0] != '\0') fprintf(out, "[%s]", flow->info);
//
//    if(flow->ssh_ssl.client_info[0] != '\0') fprintf(out, "[client: %s]", flow->ssh_ssl.client_info);
//    if(flow->ssh_ssl.server_info[0] != '\0') fprintf(out, "[server: %s]", flow->ssh_ssl.server_info);
//    if(flow->bittorent_hash[0] != '\0') fprintf(out, "[BT Hash: %s]", flow->bittorent_hash);

    fprintf(out, "\n");
  }
}
/* ***************************************************** */
void HogzillaSaveFlow(struct ndpi_flow_info *flow) {
    char str[100];

    if(flow->saved==1)
        return; /*already saved */

    //printFlow(flow);

    hbase = connectHBase();


    GPtrArray * mutations;
    mutations = g_ptr_array_new ();

    Hogzilla_mutations(flow,mutations);

    //FUTURE: HZ: find a better flow ID
    snprintf(str,100, "%lld.%lld", flow->first_seen,flow->src_ip) ;
    Text * key ;
    key = g_byte_array_new ();
    g_byte_array_append (key,(guint*) str,  strlen(str));

    check_hbase_open();

    //LogMessage("DEBUG => [Hogzilla] ID: %s , %s:%u <-> %s:%u \n", str,flow->lower_name,ntohs(flow->lower_port),flow->upper_name,ntohs(flow->upper_port));
    while(!hbase_client_mutate_row (hbase->client, table, key, mutations,attributes, &hbase->ioerror, &hbase->iargument, &hbase->error)) {
        if(hbase->error!=NULL)
            LogMessage ("%s\n", hbase->error->message);
        if(hbase->ioerror!=NULL)
            LogMessage ("%s\n", hbase->ioerror->message);
        if(hbase->iargument!=NULL)
            LogMessage ("%s\n", hbase->iargument->message);

        LogMessage("DEBUG => [Hogzilla] Error saving the flow below. Reconnecting and trying again in 10 seconds...\n\tID: %s, %s:%u <-> %s:%u [pkts:%u] \n",
                str,flow->src_name,ntohs(flow->src_port),flow->dst_name,ntohs(flow->dst_port),flow->packets);
        closeHBase();
        sleep(5);
        hbase = connectHBase();
        sleep(5);
    }

    flow->saved=1;

    g_byte_array_free(key,TRUE);
    g_ptr_array_foreach(mutations,cleanMutation,(gpointer) NULL);
    g_ptr_array_free(mutations,TRUE);
    mutations=NULL;
}
/* ***************************************************** */
static void node_idle_scan_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
    struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;

    //  idle connections, Save in HBase and remove

    if(ndpi_info.num_idle_flows == IDLE_SCAN_BUDGET){
        printf("IDLE_SCAN_BUDGET reached!\n");
        return;
    }

    if(flow->in_idle==1){
        //printf("Tried to add an idle flow again!\n");
        return;
    }

    if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
        if(flow->last_seen + HOGZILLA_MAX_IDLE_TIME < ndpi_info.last_time) {

            /* update stats */
            node_proto_guess_walker(node, which, depth, user_data);

            if((flow->detected_protocol.master_protocol == NDPI_PROTOCOL_UNKNOWN) && !undetected_flows_deleted)
                undetected_flows_deleted = 1;

            /* adding to a queue (we can't delete it from the tree inline ) */
            ndpi_info.idle_flows[ndpi_info.num_idle_flows++] = flow;
            flow->in_idle=1;
        }
    }
}
/* ***************************************************** */
static void patchIPv6Address(char *str) {
  int i = 0, j = 0;

  while(str[i] != '\0') {
    if((str[i] == ':')
       && (str[i+1] == '0')
       && (str[i+2] == ':')) {
      str[j++] = ':';
      str[j++] = ':';
      i += 3;
    } else
      str[j++] = str[i++];
  }
  if(str[j] != '\0') str[j] = '\0';
}
/* ***************************************************** */

int node_cmp(const void *a, const void *b) {
  struct ndpi_flow_info *fa = (struct ndpi_flow_info*)a;
  struct ndpi_flow_info *fb = (struct ndpi_flow_info*)b;

  if(fa->hashval < fb->hashval) return(-1); else if(fa->hashval > fb->hashval) return(1);

  /* Flows have the same hash */

  if(fa->vlan_id   < fb->vlan_id   ) return(-1); else { if(fa->vlan_id    > fb->vlan_id   ) return(1); }
  if(fa->protocol  < fb->protocol  ) return(-1); else { if(fa->protocol   > fb->protocol  ) return(1); }

  if(
     (
      (fa->src_ip      == fb->src_ip  )
      && (fa->src_port == fb->src_port)
      && (fa->dst_ip   == fb->dst_ip  )
      && (fa->dst_port == fb->dst_port)
      )
     ||
     (
      (fa->src_ip      == fb->dst_ip  )
      && (fa->src_port == fb->dst_port)
      && (fa->dst_ip   == fb->src_ip  )
      && (fa->dst_port == fb->src_port)
      )
     )
    return(0);

  if(fa->src_ip   < fb->src_ip  ) return(-1); else { if(fa->src_ip   > fb->src_ip  ) return(1); }
  if(fa->src_port < fb->src_port) return(-1); else { if(fa->src_port > fb->src_port) return(1); }
  if(fa->dst_ip   < fb->dst_ip  ) return(-1); else { if(fa->dst_ip   > fb->dst_ip  ) return(1); }
  if(fa->dst_port < fb->dst_port) return(-1); else { if(fa->dst_port > fb->dst_port) return(1); }

  return(0); /* notreached */
}


/***********************************************/
static struct ndpi_flow_info *get_ndpi_flow_info(
        const u_int8_t version,
                                 u_int16_t vlan_id,
                                 const struct ndpi_iphdr *iph,
                                 const struct ndpi_ipv6hdr *iph6,
                                 u_int16_t ip_offset,
                                 u_int16_t ipsize,
                                 u_int16_t l4_packet_len,
                                 struct ndpi_tcphdr **tcph,
                                 struct ndpi_udphdr **udph,
                                 u_int16_t *sport, u_int16_t *dport,
                                 struct ndpi_id_struct **src,
                                 struct ndpi_id_struct **dst,
                                 u_int8_t *proto,
                                 u_int8_t **payload,
                                 u_int16_t *payload_len,
                                 u_int8_t *src_to_dst_direction) {

    u_int32_t idx, l4_offset, hashval;
    struct ndpi_flow_info flow;
    void *ret;
    u_int8_t *l3, *l4;


    /*
       Note: to keep things simple (ndpiReader is just a demo app)
       we handle IPv6 a-la-IPv4.
     */
     if(version == IPVERSION) {
       if(ipsize < 20)
         return NULL;

       if((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len)
          /* || (iph->frag_off & htons(0x1FFF)) != 0 */)
         return NULL;

       l4_offset = iph->ihl * 4;
       l3 = (u_int8_t*)iph;
     } else {
       l4_offset = sizeof(struct ndpi_ipv6hdr);
       l3 = (u_int8_t*)iph6;
     }

     *proto = iph->protocol;
     l4 = ((u_int8_t *) l3 + l4_offset);

     if(iph->protocol == IPPROTO_TCP && l4_packet_len >= 20) {
       u_int tcp_len;
       // tcp
       *tcph = (struct ndpi_tcphdr *)l4;
       *sport = ntohs((*tcph)->source), *dport = ntohs((*tcph)->dest);
       tcp_len = ndpi_min(4*(*tcph)->doff, l4_packet_len);
       *payload = &l4[tcp_len];
       *payload_len = ndpi_max(0, l4_packet_len-4*(*tcph)->doff);
     } else if(iph->protocol == IPPROTO_UDP && l4_packet_len >= 8) {
       // udp
       *udph = (struct ndpi_udphdr *)l4;
       *sport = ntohs((*udph)->source), *dport = ntohs((*udph)->dest);
       *payload = &l4[sizeof(struct ndpi_udphdr)];
       *payload_len = ndpi_max(0, l4_packet_len-sizeof(struct ndpi_udphdr));
     } else {
       // non tcp/udp protocols
       *sport = *dport = 0;
     }

    flow.protocol = iph->protocol, flow.vlan_id = vlan_id;
    flow.src_ip = iph->saddr, flow.dst_ip = iph->daddr;
    flow.src_port = htons(*sport), flow.dst_port = htons(*dport);
    flow.hashval = hashval = flow.protocol + flow.vlan_id + flow.src_ip + flow.dst_ip + flow.src_port + flow.dst_port;

    idx = hashval % NUM_ROOTS;
    ret = ndpi_tfind(&flow, &ndpi_info.ndpi_flows_root[idx], node_cmp);

    if(ret == NULL) {
        if(ndpi_info.ndpi_flow_count == HOGZILLA_MAX_NDPI_FLOWS) {
            LogMessage("ERROR => [Hogzilla] maximum flow count (%u) has been exceeded\n", HOGZILLA_MAX_NDPI_FLOWS);
            exit(-1);
        } else {

            struct ndpi_flow_info *newflow = (struct ndpi_flow_info*)HzAlloc(sizeof(struct ndpi_flow_info));

            if(newflow == NULL) {
                LogMessage("ERROR => [Hogzilla] %s(1): not enough memory\n", __FUNCTION__);
                return(NULL);
            }

            memset(newflow, 0, sizeof(struct ndpi_flow_info));
            newflow->hashval = hashval;
            newflow->protocol = iph->protocol, newflow->vlan_id = vlan_id;
            newflow->src_ip = iph->saddr, newflow->dst_ip = iph->daddr;
            newflow->src_port = htons(*sport), newflow->dst_port = htons(*dport);
            newflow->ip_version = version;
            //PA NEWFLOW
            newflow->event=NULL;
            //AP

            if(version == IPVERSION) {
                inet_ntop(AF_INET, &newflow->src_ip, newflow->src_name, sizeof(newflow->src_name));
                inet_ntop(AF_INET, &newflow->dst_ip, newflow->dst_name, sizeof(newflow->dst_name));
            } else {
                inet_ntop(AF_INET6, &iph6->ip6_src, newflow->src_name, sizeof(newflow->src_name));
                inet_ntop(AF_INET6, &iph6->ip6_dst, newflow->dst_name, sizeof(newflow->dst_name));
                /* For consistency across platforms replace :0: with :: */
                patchIPv6Address(newflow->src_name), patchIPv6Address(newflow->dst_name);
            }

            if((newflow->ndpi_flow = HzAlloc(SIZEOF_FLOW_STRUCT)) == NULL) {
                LogMessage("ERROR => [Hogzilla] %s(2): not enough memory\n", __FUNCTION__);
                free(newflow);
                return(NULL);
            }

            memset(newflow->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

            if((newflow->src_id = HzAlloc(SIZEOF_ID_STRUCT)) == NULL) {
                LogMessage("ERROR => [Hogzilla] %s(3): not enough memory\n", __FUNCTION__);
                free(newflow);
                return(NULL);
            }
            memset(newflow->src_id, 0, SIZEOF_ID_STRUCT);

            if((newflow->dst_id = HzAlloc(SIZEOF_ID_STRUCT)) == NULL) {
                LogMessage("ERROR => [Hogzilla] %s(4): not enough memory\n", __FUNCTION__);
                free(newflow);
                return(NULL);
            }
            memset(newflow->dst_id, 0, SIZEOF_ID_STRUCT);

            ndpi_tsearch(newflow, &ndpi_info.ndpi_flows_root[idx], node_cmp); /* Add */
            ndpi_info.ndpi_flow_count++;

            *src = newflow->src_id, *dst = newflow->dst_id;



            return newflow ;
        }
    } else {
        struct ndpi_flow_info *flow = *(struct ndpi_flow_info**)ret;

        if(flow->src_ip == iph->saddr
           && flow->dst_ip == iph->daddr
           && flow->src_port == htons(*sport)
           && flow->dst_port == htons(*dport)
           )
          *src = flow->src_id, *dst = flow->dst_id, *src_to_dst_direction = 1;
        else
          *src = flow->dst_id, *dst = flow->src_id, *src_to_dst_direction = 0, flow->bidirectional = 1;

        return flow;
    }
}
/* ***************************************************** */
static struct ndpi_flow_info *get_ndpi_flow_info6(
                          u_int16_t vlan_id,
                          const struct ndpi_ipv6hdr *iph6,
                          u_int16_t ip_offset,
                          struct ndpi_tcphdr **tcph,
                          struct ndpi_udphdr **udph,
                          u_int16_t *sport, u_int16_t *dport,
                          struct ndpi_id_struct **src,
                          struct ndpi_id_struct **dst,
                          u_int8_t *proto,
                          u_int8_t **payload,
                          u_int16_t *payload_len,
                          u_int8_t *src_to_dst_direction) {
  struct ndpi_iphdr iph;

  memset(&iph, 0, sizeof(iph));
  iph.version = IPVERSION;
  iph.saddr = iph6->ip6_src.u6_addr.u6_addr32[2] + iph6->ip6_src.u6_addr.u6_addr32[3];
  iph.daddr = iph6->ip6_dst.u6_addr.u6_addr32[2] + iph6->ip6_dst.u6_addr.u6_addr32[3];
  iph.protocol = iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt;

  if(iph.protocol == IPPROTO_DSTOPTS /* IPv6 destination option */) {
    u_int8_t *options = (u_int8_t*)iph6 + sizeof(const struct ndpi_ipv6hdr);

    iph.protocol = options[0];
  }

  return(get_ndpi_flow_info(6, vlan_id, &iph, iph6, ip_offset,
                sizeof(struct ndpi_ipv6hdr),
                ntohs(iph6->ip6_ctlun.ip6_un1.ip6_un1_plen),
                tcph, udph, sport, dport,
                src, dst, proto, payload, payload_len, src_to_dst_direction));
}
/* ***************************************************** */
void variation_comput(u_int32_t *expected,u_int32_t * variationSum, u_int32_t currentSize){
	if(currentSize!=NULL){
		if(*expected==0&&currentSize!=0)
			*expected=currentSize;
		else if(*expected==0)
			*expected=1;
        //*variationSum+= (((currentSize-(*expected))*(currentSize-(*expected)))*100)/(*expected);
        *variationSum+= ((abs(currentSize-(*expected)))*100)/(*expected);
		*expected = (9*(*expected)+currentSize)/10;
	}
}
/* ***************************************************** */
static void updateFlowFeatures(struct ndpi_flow_info *flow,
        u_int64_t time1,
        u_int16_t vlan_id,
        const struct ndpi_iphdr *iph,
        struct ndpi_ipv6hdr *iph6,
        u_int16_t ip_offset,
        u_int16_t ipsize,
        u_int16_t rawsize,
        u_int8_t src_to_dst_direction,
        struct ndpi_tcphdr *tcph,
        struct ndpi_udphdr *udph,
        u_int8_t proto,
        u_int8_t *payload,
        u_int16_t payload_len) {

    uint8_t* opt;
    uint16_t mss;
    uint8_t wscale=0;



    struct ndpi_flow_struct *ndpi_flow = flow->ndpi_flow;

    if(flow->packets==0) {
        // TODO: DEBUG
        //flow->last_seen = 1503215322763;
        //flow->last_seen = time1;
    }



    // TODO: DEBUG
    return ;


    if(flow->packets<HOGZILLA_MAX_NDPI_PKT_PER_FLOW) {
        flow->arrival_time[flow->packets] = time1;
        flow->inter_time[flow->packets] = time1 - flow->last_seen;
        flow->packet_pay_size[flow->packets]=payload_len;
        flow->packet_header_size[flow->packets]=ipsize-payload_len;
        flow->direction[flow->packets]=src_to_dst_direction;
    }




    flow->packets++, flow->bytes += rawsize;
    flow->last_seen = time1;

    flow->payload_bytes += payload_len;
    if(flow->packets==1)
    {
        flow->payload_bytes_first = payload_len;
        flow->first_seen=time1;
    }

    if(src_to_dst_direction)
      flow->src2dst_packets++, flow->src2dst_pay_bytes += payload_len, flow->src2dst_header_bytes+=ipsize-payload_len;
    else
      flow->dst2src_packets++, flow->dst2src_pay_bytes += payload_len, flow->dst2src_header_bytes+=ipsize-payload_len;

    if(payload_len==0)
        flow->packets_without_payload++;

    flow->flow_duration = time1 - flow->first_seen;

    // TODO: DEBUG
    return ;

    variation_comput(&flow->payload_size_variation_expected,&flow->payload_size_variation,(u_int32_t)payload_len);

    if(proto == IPPROTO_TCP){
        flow->packets_syn += tcph->syn;
        flow->packets_ack += tcph->ack;
        flow->packets_fin += tcph->fin;
        flow->packets_rst += tcph->rst;
        flow->packets_psh += tcph->psh;
        flow->packets_urg += tcph->urg;
        flow->tcp_retransmissions += ndpi_flow->packet.tcp_retransmission;

        /*
         * HTTP times
         */
        if(ndpi_flow->http_detected){
            if(ndpi_flow->l4.tcp.http_stage==1 && flow->request_abs_time == 0){
             /* HTTP Request */
                flow->request_abs_time=time1;
            }else if(ndpi_flow->packet.http_response.len >0 && flow->request_abs_time > 0 && flow->response_rel_time==0){
             /* HTTP Response */
                flow->response_rel_time=time1-flow->request_abs_time;
            }
        }
    }else if(proto == IPPROTO_UDP &&
            (flow->detected_protocol.master_protocol==NDPI_PROTOCOL_DNS ||
                    flow->detected_protocol.app_protocol==NDPI_PROTOCOL_DNS ) &&
                    payload_len > sizeof(struct ndpi_dns_packet_header)){

        struct ndpi_dns_packet_header dns_header;
        int is_query=-1;

        memcpy(&dns_header, (struct ndpi_dns_packet_header*) payload, sizeof(struct ndpi_dns_packet_header));
        dns_header.tr_id          = ntohs(dns_header.tr_id);
        dns_header.flags          = ntohs(dns_header.flags);
        dns_header.num_queries    = ntohs(dns_header.num_queries);
        dns_header.num_answers    = ntohs(dns_header.num_answers);
        dns_header.authority_rrs  = ntohs(dns_header.authority_rrs);
        dns_header.additional_rrs = ntohs(dns_header.additional_rrs);

        /* 0x0000 QUERY */
        if((dns_header.flags & DNS_FLAGS_MASK) == 0x0000)
            is_query = 1;
        /* 0x8000 RESPONSE */
        else if((dns_header.flags & DNS_FLAGS_MASK) == 0x8000)
            is_query = 0;

        if(is_query==1 && flow->request_abs_time == 0){
            /* DNS Request */
            flow->request_abs_time=time1;
        }else if(is_query==0 && flow->request_abs_time > 0 && flow->response_rel_time==0){
            /* DNS Response */
            flow->response_rel_time=time1-flow->request_abs_time;
        }
    }

    /* Count contacts */
    if(payload_len >= CONTACT_NEGLIGIBLE_PAYLOAD && flow->C_number_of_contacts <= MAX_CONTACTS){ /* in contact */

        if(time1 - flow->C_last_time >= CONTACT_MIN_INTERTIME) { /* new contact */
            flow->C_number_of_contacts++;

            /* Update last contact features */
            if(flow->C_number_of_contacts>=2){
                flow->C_idletime[flow->C_number_of_contacts-2]=time1 - flow->C_last_time;
            }

            if(flow->C_number_of_contacts<= MAX_CONTACTS)
                flow->C_start_time[flow->C_number_of_contacts-1] = time1;
        }

        if(flow->C_number_of_contacts<= MAX_CONTACTS) {
            /*  statistics for the current contact */
            if(src_to_dst_direction){
                flow->C_src2dst_pay_bytes[flow->C_number_of_contacts-1]+= payload_len;
                flow->C_src2dst_packets[flow->C_number_of_contacts-1]++;
                flow->C_src2dst_header_bytes[flow->C_number_of_contacts-1]+= ipsize-payload_len;
            }else{
                flow->C_dst2src_pay_bytes[flow->C_number_of_contacts-1]+= payload_len;
                flow->C_dst2src_packets[flow->C_number_of_contacts-1]++;
                flow->C_dst2src_header_bytes[flow->C_number_of_contacts-1]+= ipsize-payload_len;
            }

            if(proto == IPPROTO_TCP){
                flow->C_packets_syn[flow->C_number_of_contacts-1] += tcph->syn;
                flow->C_packets_ack[flow->C_number_of_contacts-1] += tcph->ack;
                flow->C_packets_fin[flow->C_number_of_contacts-1] += tcph->fin;
                flow->C_packets_rst[flow->C_number_of_contacts-1] += tcph->rst;
                flow->C_packets_psh[flow->C_number_of_contacts-1] += tcph->psh;
                flow->C_packets_urg[flow->C_number_of_contacts-1] += tcph->urg;
                flow->C_tcp_retransmissions[flow->C_number_of_contacts-1] += ndpi_flow->packet.tcp_retransmission;
            }
            /* duration of current contact */
            flow->C_duration[flow->C_number_of_contacts-1]=time1-flow->C_start_time[flow->C_number_of_contacts-1];

            /* last valid contact */
            flow->C_last_time = time1;
        }
    }




}
/* *****************************************************
 *
 * (filter[i]+not)%2 - filter in {0,1} and not={0,1}
 *
 *  */

static void avg_min_max_std(u_int64_t *series,int series_size, u_int8_t *filter, int not, int avoidZeroValues,
		u_int64_t *avg, u_int64_t *min, u_int64_t *max, u_int64_t *std){

    int i;
    u_int64_t counter=0;
    *min=18446744073709551615;
    *max=0;
    *avg=0;
    *std=0;

    for(i=0; i<series_size ;i++ ){
        if(!( filter==NULL || (not^(filter[i]==1)) ) || (avoidZeroValues==1 && series[i] ==0 ))
            continue;

        if(series[i] < *min)
            *min = series[i];
        if(series[i] > *max)
            *max = series[i];
        *avg+=series[i];
        counter++;
    }


    if(counter!=0)
        *avg=*avg/counter;


    for(i=0; i<series_size ;i++ ){

        if(!( filter==NULL || (not^(filter[i]==1)) ) || (avoidZeroValues==1 && series[i] ==0 ) )
            continue;

        *std += (*avg-series[i])*(*avg-series[i]);
    }

    if(counter!=0)
        *std=*std/counter;
    else
        *min=0;

    *std=sqrt(*std);

}

/* ***************************************************** */

static u_int64_t sum_series(u_int64_t *series,int series_size){
	int i; u_int64_t counter;
	counter=0;
	for(i=0;i<series_size;i++)
		counter += series[i];
	return counter;
}
/* ***************************************************** */

static void updateFlowCountsBeforeInsert(struct ndpi_flow_info *flow){



    int series_size,i;

    flow->flow_duration=flow->last_seen-flow->first_seen;

    series_size=ndpi_min(flow->C_number_of_contacts,MAX_CONTACTS);

    for(i=0;i<series_size;i++){
        if(flow->C_duration[i]!=0){
              flow->C_dst2src_pay_bytes_rate[i] = flow->C_dst2src_pay_bytes[i]/flow->C_duration[i];
              flow->C_src2dst_pay_bytes_rate[i] = flow->C_src2dst_pay_bytes[i]/flow->C_duration[i];
              flow->C_dst2src_packets_rate[i]   = (flow->C_dst2src_packets[i]*1000)/flow->C_duration[i];
              flow->C_src2dst_packets_rate[i]   = (flow->C_src2dst_packets[i]*1000)/flow->C_duration[i];
          }
    }

    for(i=0;i<series_size-1;i++){
        flow->C_inter_start_time[i]=flow->C_start_time[i+1]-flow->C_start_time[i];
    }

    avg_min_max_std(flow->C_inter_start_time,series_size-1, NULL, 0,0,&flow->C_inter_start_time_avg,
                &flow->C_inter_start_time_min,&flow->C_inter_start_time_max,&flow->C_inter_start_time_std);
    avg_min_max_std(flow->C_src2dst_pay_bytes,series_size, NULL, 0,1,&flow->C_src2dst_pay_bytes_avg,
                    &flow->C_src2dst_pay_bytes_min,&flow->C_src2dst_pay_bytes_max,&flow->C_src2dst_pay_bytes_std);
    avg_min_max_std(flow->C_src2dst_header_bytes,series_size, NULL, 0,0, &flow->C_src2dst_header_bytes_avg, 
                    &flow->C_src2dst_header_bytes_min, &flow->C_src2dst_header_bytes_max, &flow->C_src2dst_header_bytes_std);
    avg_min_max_std(flow->C_src2dst_packets,series_size, NULL, 0,0, &flow->C_src2dst_packets_avg,
                    &flow->C_src2dst_packets_min, &flow->C_src2dst_packets_max, &flow->C_src2dst_packets_std);
    avg_min_max_std(flow->C_dst2src_pay_bytes,series_size, NULL, 0,1, &flow->C_dst2src_pay_bytes_avg,
                    &flow->C_dst2src_pay_bytes_min, &flow->C_dst2src_pay_bytes_max, &flow->C_dst2src_pay_bytes_std);
    avg_min_max_std(flow->C_dst2src_header_bytes,series_size, NULL, 0,0,&flow->C_dst2src_header_bytes_avg,
                    &flow->C_dst2src_header_bytes_min, &flow->C_dst2src_header_bytes_max, &flow->C_dst2src_header_bytes_std);
    avg_min_max_std(flow->C_dst2src_packets,series_size, NULL, 0,0,&flow->C_dst2src_packets_avg,
                    &flow->C_dst2src_packets_min, &flow->C_dst2src_packets_max, &flow->C_dst2src_packets_std);
    avg_min_max_std(flow->C_packets_syn,series_size, NULL, 0,0, &flow->C_packets_syn_avg,
                    &flow->C_packets_syn_min, &flow->C_packets_syn_max, &flow->C_packets_syn_std);
    avg_min_max_std(flow->C_packets_ack,series_size, NULL, 0,0, &flow->C_packets_ack_avg,
                    &flow->C_packets_ack_min, &flow->C_packets_ack_max, &flow->C_packets_ack_std);
    avg_min_max_std(flow->C_packets_fin,series_size, NULL, 0,0, &flow->C_packets_fin_avg,
                    &flow->C_packets_fin_min, &flow->C_packets_fin_max, &flow->C_packets_fin_std);
    avg_min_max_std(flow->C_packets_rst,series_size, NULL, 0,0, &flow->C_packets_rst_avg,
                    &flow->C_packets_rst_min, &flow->C_packets_rst_max, &flow->C_packets_rst_std);
    avg_min_max_std(flow->C_packets_psh,series_size, NULL, 0,0, &flow->C_packets_psh_avg,
                    &flow->C_packets_psh_min, &flow->C_packets_psh_max, &flow->C_packets_psh_std);
    avg_min_max_std(flow->C_packets_urg,series_size, NULL, 0,0, &flow->C_packets_urg_avg,
                    &flow->C_packets_urg_min, &flow->C_packets_urg_max, &flow->C_packets_urg_std);
    avg_min_max_std(flow->C_tcp_retransmissions,series_size, NULL, 0,0, &flow->C_tcp_retransmissions_avg,
                    &flow->C_tcp_retransmissions_min, &flow->C_tcp_retransmissions_max, &flow->C_tcp_retransmissions_std);
    avg_min_max_std(flow->C_dst2src_pay_bytes_rate,series_size, NULL, 0,0, &flow->C_dst2src_pay_bytes_rate_avg,
                    &flow->C_dst2src_pay_bytes_rate_min, &flow->C_dst2src_pay_bytes_rate_max, &flow->C_dst2src_pay_bytes_rate_std);
    avg_min_max_std(flow->C_src2dst_pay_bytes_rate, series_size, NULL, 0,0, &flow->C_src2dst_pay_bytes_rate_avg,
                    &flow->C_src2dst_pay_bytes_rate_min, &flow->C_src2dst_pay_bytes_rate_max, &flow->C_src2dst_pay_bytes_rate_std);
    avg_min_max_std(flow->C_dst2src_packets_rate, series_size, NULL, 0,0, &flow->C_dst2src_packets_rate_avg,
                    &flow->C_dst2src_packets_rate_min, &flow->C_dst2src_packets_rate_max, &flow->C_dst2src_packets_rate_std);
    avg_min_max_std(flow->C_src2dst_packets_rate, series_size, NULL, 0,0, &flow->C_src2dst_packets_rate_avg,
                    &flow->C_src2dst_packets_rate_min, &flow->C_src2dst_packets_rate_max, &flow->C_src2dst_packets_rate_std);
    avg_min_max_std(flow->C_duration, series_size, NULL, 0,0, &flow->C_duration_avg,
                    &flow->C_duration_min, &flow->C_duration_max, &flow->C_duration_std);
    avg_min_max_std(flow->C_idletime, series_size-1, NULL, 0,0, &flow->C_idletime_avg, /* idle between contacts */
                    &flow->C_idletime_min, &flow->C_idletime_max, &flow->C_idletime_std);

    flow->flow_use_time=sum_series(flow->C_duration, series_size);
    flow->flow_idle_time=flow->flow_duration-flow->flow_use_time;



    series_size=ndpi_min(flow->packets,HOGZILLA_MAX_NDPI_PKT_PER_FLOW);

    avg_min_max_std(flow->packet_header_size, series_size, flow->direction, 0,0, &flow->src2dst_header_bytes_avg,
                    &flow->src2dst_header_bytes_min, &flow->src2dst_header_bytes_max, &flow->src2dst_header_bytes_std);
    avg_min_max_std(flow->packet_pay_size, series_size, flow->direction, 1,1, &flow->dst2src_pay_bytes_avg,
                    &flow->dst2src_pay_bytes_min, &flow->dst2src_pay_bytes_max, &flow->dst2src_pay_bytes_std);
    avg_min_max_std(flow->packet_header_size, series_size, flow->direction, 1,0, &flow->dst2src_header_bytes_avg,
                    &flow->dst2src_header_bytes_min, &flow->dst2src_header_bytes_max, &flow->dst2src_header_bytes_std);
    avg_min_max_std(flow->packet_pay_size, series_size, flow->direction, 0,1, &flow->src2dst_pay_bytes_avg,
                    &flow->src2dst_pay_bytes_min, &flow->src2dst_pay_bytes_max, &flow->src2dst_pay_bytes_std);

    int s2dc,d2sc;
    u_int64_t s2dlast,d2slast;
    s2dc=d2sc=0;
    s2dlast=flow->first_seen;
    d2slast=flow->first_seen;
    u_int64_t inter_time_src2dst[HOGZILLA_MAX_NDPI_PKT_PER_FLOW],
			  inter_time_dst2src[HOGZILLA_MAX_NDPI_PKT_PER_FLOW];

    for(i=0;i<series_size;i++){
    	if(flow->direction[i]){
    		inter_time_src2dst[s2dc] = flow->arrival_time[i] - s2dlast;
    		s2dlast=flow->arrival_time[i];
    		s2dc++;
    	}else{
    		inter_time_dst2src[d2sc] = flow->arrival_time[i] - d2slast;
    		d2slast=flow->arrival_time[i];
    		d2sc++;
    	}
    }

    avg_min_max_std(inter_time_src2dst, s2dc, NULL, 0,0, &flow->src2dst_inter_time_avg,
                    &flow->src2dst_inter_time_min, &flow->src2dst_inter_time_max, &flow->src2dst_inter_time_std);
    avg_min_max_std(inter_time_dst2src, d2sc, NULL, 0,0, &flow->dst2src_inter_time_avg,
                    &flow->dst2src_inter_time_min, &flow->dst2src_inter_time_max, &flow->dst2src_inter_time_std);


    avg_min_max_std(flow->inter_time, series_size, NULL, 0,0, &flow->inter_time_avg,
                     &flow->inter_time_min, &flow->inter_time_max, &flow->inter_time_std);

    avg_min_max_std(flow->packet_pay_size, series_size, NULL, 0,0, &flow->payload_bytes_avg,
                     &flow->payload_bytes_min, &flow->payload_bytes_max, &flow->payload_bytes_std);

    if(flow->flow_duration!=0){
    	flow->dst2src_pay_bytes_rate = flow->dst2src_pay_bytes/flow->flow_duration;
    	flow->src2dst_pay_bytes_rate = flow->src2dst_pay_bytes/flow->flow_duration;
    	flow->dst2src_packets_rate = (flow->dst2src_packets*1000)/flow->flow_duration;
    	flow->src2dst_packets_rate = (flow->src2dst_packets*1000)/flow->flow_duration;
    }


}
/* ***************************************************** */

static struct ndpi_flow_info *packet_processing_by_pcap(const struct pcap_pkthdr *header, const u_char *packet) {

    const struct ndpi_ethhdr *ethernet;
    struct ndpi_iphdr *iph;
    struct ndpi_ipv6hdr *iph6;
    u_int64_t time;
    u_int16_t type, ip_offset, ip_len;
    u_int16_t frag_off = 0, vlan_id = 0;
    u_int8_t proto = 0, vlan_packet = 0;

    // printf("[ndpiReader] pcap_packet_callback : [%u.%u.%u.%u.%u -> %u.%u.%u.%u.%u]\n", ethernet->h_dest[1],ethernet->h_dest[2],ethernet->h_dest[3],ethernet->h_dest[4],ethernet->h_dest[5],ethernet->h_source[1],ethernet->h_source[2],ethernet->h_source[3],ethernet->h_source[4],ethernet->h_source[5]);

    time = ((uint64_t) header->ts.tv_sec) * TICK_RESOLUTION +
            header->ts.tv_usec / (1000000 / TICK_RESOLUTION);

    if(ndpi_info.last_time > time) { /* safety check */
        //printf("\nWARNING: timestamp bug in the pcap file (ts delta: %llu, repairing)\n", ndpi_info.last_time - time);
        time = ndpi_info.last_time;
    }
    ndpi_info.last_time = time;

    //if(ndpi_info._pcap_datalink_type == DLT_NULL) {
    //if(ntohl(*((u_int32_t*)packet)) == 2)
    //  type = ETH_P_IP;
    //else
    //  type = 0x86DD; /* IPv6 */

    //ip_offset = 4;
    //} else if(ndpi_info._pcap_datalink_type == DLT_EN10MB) {
    ethernet = (struct ndpi_ethhdr *) packet;
    ip_offset = sizeof(struct ndpi_ethhdr);
    type = ntohs(ethernet->h_proto);
    //} else if(ndpi_info._pcap_datalink_type == 113 /* Linux Cooked Capture */) {
    //  type = (packet[14] << 8) + packet[15];
    //  ip_offset = 16;
    //} else
    //  return;

    while(1) {
        if(type == 0x8100 /* VLAN */) {
            vlan_id = ((packet[ip_offset] << 8) + packet[ip_offset+1]) & 0xFFF;
            type = (packet[ip_offset+2] << 8) + packet[ip_offset+3];
            ip_offset += 4;
            vlan_packet = 1;
        } else if(type == 0x8847 /* MPLS */) {
            u_int32_t label = ntohl(*((u_int32_t*)&packet[ip_offset]));

            type = 0x800, ip_offset += 4;

            while((label & 0x100) != 0x100) {
                ip_offset += 4;
                label = ntohl(*((u_int32_t*)&packet[ip_offset]));
            }
        } else if(type == 0x8864 /* PPPoE */) {
            type = 0x0800;
            ip_offset += 8;
        } else
            break;
    }


    iph = (struct ndpi_iphdr *) &packet[ip_offset];

    // just work on Ethernet packets that contain IP
    if(type == ETH_P_IP && header->caplen >= ip_offset) {
        frag_off = ntohs(iph->frag_off);

        proto = iph->protocol;
        if(header->caplen < header->len) {
            static u_int8_t cap_warning_used = 0;

            if(cap_warning_used == 0) {
                LogMessage("\n\nWARNING: packet capture size is smaller than packet size, DETECTION MIGHT NOT WORK CORRECTLY\n\n");
                cap_warning_used = 1;
            }
        }
    }

    if(iph->version == 4) {
        ip_len = ((u_short)iph->ihl * 4);
        iph6 = NULL;

        if((frag_off & 0x3FFF) != 0) {
            static u_int8_t ipv4_frags_warning_used = 0;

            if(ipv4_frags_warning_used == 0) {
                LogMessage("\n\nWARNING: IPv4 fragments are not handled by this demo (nDPI supports them)\n");
                ipv4_frags_warning_used = 1;
            }

            return NULL;
        }
    } else if(iph->version == 6) {
        iph6 = (struct ndpi_ipv6hdr *)&packet[ip_offset];
        proto = iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        ip_len = sizeof(struct ndpi_ipv6hdr);

        if(proto == 0x3C /* IPv6 destination option */) {
            u_int8_t *options = (u_int8_t*)&packet[ip_offset+ip_len];

            proto = options[0];
            ip_len += 8 * (options[1] + 1);
        }

        iph = NULL;
    } else {
        static u_int8_t ipv4_warning_used = 0;

        v4_warning:
        if(ipv4_warning_used == 0) {
            LogMessage("\n\nWARNING: only IPv4/IPv6 packets are supported in this demo (nDPI supports both IPv4 and IPv6), all other packets will be discarded\n\n");
            ipv4_warning_used = 1;
        }

        return NULL;
    }

    if(decode_tunnels && (proto == IPPROTO_UDP)) {
        struct ndpi_udphdr *udp = (struct ndpi_udphdr *)&packet[ip_offset+ip_len];
        u_int16_t sport = ntohs(udp->source), dport = ntohs(udp->dest);

        if((sport == GTP_U_V1_PORT) || (dport == GTP_U_V1_PORT)) {
            /* Check if it's GTPv1 */
            u_int offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr);
            u_int8_t flags = packet[offset];
            u_int8_t message_type = packet[offset+1];

            if((((flags & 0xE0) >> 5) == 1 /* GTPv1 */) && (message_type == 0xFF /* T-PDU */)) {
                ip_offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr)+8 /* GTPv1 header len */;

                if(flags & 0x04) ip_offset += 1; /* next_ext_header is present */
                if(flags & 0x02) ip_offset += 4; /* sequence_number is present (it also includes next_ext_header and pdu_number) */
                if(flags & 0x01) ip_offset += 1; /* pdu_number is present */

                iph = (struct ndpi_iphdr *) &packet[ip_offset];

                if(iph->version != 4) {
                    // printf("WARNING: not good (packet_id=%u)!\n", (unsigned int)ndpi_info.stats.raw_packet_count);
                    goto v4_warning;
                }
            }
        }
    }

    // process the packet
    return packet_processing(time, vlan_id, iph, iph6, ip_offset, header->len - ip_offset, header->len);
}

/* ***************************************************** */
void process_ndpi_collected_info(struct ndpi_flow_info *flow) {
    if(!flow->ndpi_flow) return;

//    Not using for now
//    snprintf(flow->host_server_name, sizeof(flow->host_server_name), "%s",
//            flow->ndpi_flow->host_server_name);
//
//    /* BITTORRENT */
//    if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_BITTORRENT) {
//        int i, j, n = 0;
//
//        for(i=0, j = 0; j < sizeof(flow->bittorent_hash)-1; i++) {
//            sprintf(&flow->bittorent_hash[j], "%02x", flow->ndpi_flow->bittorent_hash[i]);
//            j += 2, n += flow->ndpi_flow->bittorent_hash[i];
//        }
//
//        if(n == 0) flow->bittorent_hash[0] = '\0';
//    }
//    /* MDNS */
//    else if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_MDNS) {
//        snprintf(flow->info, sizeof(flow->info), "%s", flow->ndpi_flow->protos.mdns.answer);
//    }
//    /* UBNTAC2 */
//    else if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UBNTAC2) {
//        snprintf(flow->info, sizeof(flow->info), "%s", flow->ndpi_flow->protos.ubntac2.version);
//    }
//    if(flow->detected_protocol.app_protocol != NDPI_PROTOCOL_DNS) {
//        /* SSH */
//        if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_SSH) {
//            snprintf(flow->ssh_ssl.client_info, sizeof(flow->ssh_ssl.client_info), "%s",
//                    flow->ndpi_flow->protos.ssh.client_signature);
//            snprintf(flow->ssh_ssl.server_info, sizeof(flow->ssh_ssl.server_info), "%s",
//                    flow->ndpi_flow->protos.ssh.server_signature);
//        }
//        /* SSL */
//        else if((flow->detected_protocol.app_protocol == NDPI_PROTOCOL_SSL)
//                || (flow->detected_protocol.master_protocol == NDPI_PROTOCOL_SSL)) {
//            snprintf(flow->ssh_ssl.client_info, sizeof(flow->ssh_ssl.client_info), "%s",
//                    flow->ndpi_flow->protos.ssl.client_certificate);
//            snprintf(flow->ssh_ssl.server_info, sizeof(flow->ssh_ssl.server_info), "%s",
//                    flow->ndpi_flow->protos.ssl.server_certificate);
//        }
//    }


}
/* ***************************************************** */
static struct ndpi_flow_info *packet_processing( const u_int64_t time1,
        u_int16_t vlan_id,
        const struct ndpi_iphdr *iph,
        struct ndpi_ipv6hdr *iph6,
        u_int16_t ip_offset,
        u_int16_t ipsize, u_int16_t rawsize) {


    struct ndpi_id_struct *src, *dst;
    struct ndpi_flow_info *flow = NULL;
    struct ndpi_flow_struct *ndpi_flow = NULL;
    u_int8_t proto;
    struct ndpi_tcphdr *tcph = NULL;
    struct ndpi_udphdr *udph = NULL;
    u_int16_t sport, dport, payload_len;
    u_int8_t *payload;
    u_int8_t src_to_dst_direction = 1;
    struct ndpi_proto nproto = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN };
    struct ndpi_packet_struct *packet;


    if(iph)
      flow = get_ndpi_flow_info(IPVERSION, vlan_id, iph, NULL,
                    ip_offset, ipsize,
                    ntohs(iph->tot_len) - (iph->ihl * 4),
                    &tcph, &udph, &sport, &dport,
                    &src, &dst, &proto,
                    &payload, &payload_len, &src_to_dst_direction);
    else
      flow = get_ndpi_flow_info6(vlan_id, iph6, ip_offset,
                     &tcph, &udph, &sport, &dport,
                     &src, &dst, &proto,
                     &payload, &payload_len, &src_to_dst_direction);

    if(flow != NULL) {
        ndpi_flow = flow->ndpi_flow;
    } else { // flow is NULL
      return(NULL);
    }

    // TODO: DEBUG
//    if(flow->detection_completed) {
//        if(flow->check_extra_packets && ndpi_flow != NULL && ndpi_flow->check_extra_packets) {
//            if(ndpi_flow->num_extra_packets_checked == 0 && ndpi_flow->max_extra_packets_to_check == 0) {
//                /* Protocols can set this, but we set it here in case they didn't */
//                ndpi_flow->max_extra_packets_to_check = MAX_EXTRA_PACKETS_TO_CHECK;
//            }
//            if(ndpi_flow->num_extra_packets_checked < ndpi_flow->max_extra_packets_to_check) {
//                ndpi_process_extra_packet(ndpi_info.ndpi_struct, ndpi_flow,
//                        iph ? (uint8_t *)iph : (uint8_t *)iph6,
//                                ipsize, time1, src, dst);
//                if (ndpi_flow->check_extra_packets == 0) {
//                    flow->check_extra_packets = 0;
//                    process_ndpi_collected_info(flow);
//                }
//            }
//        }
//
//    }else{
//
//        flow->detected_protocol = ndpi_detection_process_packet(ndpi_info.ndpi_struct, ndpi_flow,
//                iph ? (uint8_t *)iph : (uint8_t *)iph6,
//                        ipsize, time1, src, dst);
//
//        if((flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN)
//                || ((proto == IPPROTO_UDP) && ((flow->src2dst_packets + flow->dst2src_packets) > 8))
//                || ((proto == IPPROTO_TCP) && ((flow->src2dst_packets + flow->dst2src_packets) > 10))) {
//            /* New protocol detected or give up */
//            flow->detection_completed = 1;
//            /* Check if we should keep checking extra packets */
//            if (ndpi_flow->check_extra_packets)
//                flow->check_extra_packets = 1;
//
//            if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN)
//                flow->detected_protocol = ndpi_detection_giveup(ndpi_info.ndpi_struct,flow->ndpi_flow);
//
//            process_ndpi_collected_info(flow);
//        }
//    }

    // TODO: DEBUG
    if(flow->packets==0)
        (*flow).last_seen = time1;

    updateFlowFeatures(flow,time1,vlan_id,iph,iph6,ip_offset,ipsize,rawsize,src_to_dst_direction,tcph, udph,proto,payload,payload_len);

    // After FIN , save into HBase and remove from tree
    if(iph!=NULL && iph->protocol == IPPROTO_TCP && tcph!=NULL){
        if(tcph->fin == 1) flow->fin_stage++;

        if(flow->fin_stage==2 && tcph->fin == 0 && tcph->ack == 1){ /* Connection finished! */
            // TODO: DEBUG
            //HogzillaSaveFlow(flow);
        }
    }

    // 500 packets, save it into HBASE
    if( flow->packets == HOGZILLA_MAX_NDPI_PKT_PER_FLOW) {
       //TODO: DEBUG
        //HogzillaSaveFlow(flow); /* save into  HBase */
    }

    scan_idle_flows();

    return flow;
}



static void closeHBase(void) {
    thrift_transport_close (hbase->transport, NULL);
    g_object_unref (hbase->client);
    g_object_unref (hbase->protocol);
    g_object_unref (hbase->transport);
    g_object_unref (hbase->socket);
    free(hbase);
    hbase = NULL;
}
struct HogzillaHBase *connectHBase() {

    // Verifica se está aberta ou não
    if(hbase != NULL){return hbase;}

    //struct HogzillaHBase *hbase;
    hbase = (HogzillaHBase*) HzAlloc(sizeof(HogzillaHBase));

#if (!GLIB_CHECK_VERSION (2, 36, 0))
    g_type_init ();
#endif

    hbase->socket    = g_object_new (THRIFT_TYPE_SOCKET,
            "hostname",  hogzilla_ptr->hbase_host,
            "port",      hogzilla_ptr->hbase_port,
            NULL);
    hbase->transport = g_object_new (THRIFT_TYPE_BUFFERED_TRANSPORT,
            "transport", hbase->socket,
            NULL);
    hbase->protocol  = g_object_new (THRIFT_TYPE_BINARY_PROTOCOL,
            "transport", hbase->transport,
            NULL);

    thrift_transport_open (hbase->transport, &hbase->error);

    hbase->client = g_object_new (TYPE_HBASE_CLIENT,
            "input_protocol",  hbase->protocol,
            "output_protocol", hbase->protocol,
            NULL);
    return hbase;
}


void Hogzilla_mutations(struct ndpi_flow_info *flow, GPtrArray * mutations) {



    int c=0, textSize=50;
    char text[200][textSize+1];
    Mutation *mutation;

    for(c=0;c<textSize;c++)
       text[c][textSize+1]='\0';

    c=0;

    updateFlowCountsBeforeInsert(flow);

//  There is a limitation on the len of mutations. We are commenting these features which are not so useful
//    for our current purposes
//    // first_seen  c=0
//    snprintf(text[c], textSize, "%ld", flow->first_seen);
//    mutation = g_object_new (TYPE_MUTATION, NULL);
//    mutation->column = g_byte_array_new ();
//    mutation->value  = g_byte_array_new ();
//    g_byte_array_append (mutation->column,(guint*) "flow:first_seen", 15);
//    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
//    g_ptr_array_add (mutations, mutation);
//    c++;
//
//    // bittorent_hash
//    mutation = g_object_new (TYPE_MUTATION, NULL);
//    mutation->column = g_byte_array_new ();
//    mutation->value  = g_byte_array_new ();
//    g_byte_array_append (mutation->column,(guint*)  "flow:bittorent_hash", 19);
//    g_byte_array_append (mutation->value ,(guint**) flow->bittorent_hash,  strlen(flow->bittorent_hash));
//    g_ptr_array_add (mutations, mutation);
//
//    // info
//    mutation = g_object_new (TYPE_MUTATION, NULL);
//    mutation->column = g_byte_array_new ();
//    mutation->value  = g_byte_array_new ();
//    g_byte_array_append (mutation->column,(guint*)  "flow:info", 9);
//    g_byte_array_append (mutation->value ,(guint**) flow->info,  strlen(flow->info));
//    g_ptr_array_add (mutations, mutation);
//
//    // host_server_name
//    mutation = g_object_new (TYPE_MUTATION, NULL);
//    mutation->column = g_byte_array_new ();
//    mutation->value  = g_byte_array_new ();
//    g_byte_array_append (mutation->column,(guint*)  "flow:host_server_name", 21);
//    g_byte_array_append (mutation->value ,(guint**) flow->host_server_name,  strlen(flow->host_server_name));
//    g_ptr_array_add (mutations, mutation);
//
//    // ssh_ssl.client_info
//    mutation = g_object_new (TYPE_MUTATION, NULL);
//    mutation->column = g_byte_array_new ();
//    mutation->value  = g_byte_array_new ();
//    g_byte_array_append (mutation->column,(guint*)  "flow:ssh_ssl_client_info", 24);
//    g_byte_array_append (mutation->value ,(guint**) flow->ssh_ssl.client_info,  strlen(flow->ssh_ssl.client_info));
//    g_ptr_array_add (mutations, mutation);
//
//    // ssh_ssl.server_info
//    mutation = g_object_new (TYPE_MUTATION, NULL);
//    mutation->column = g_byte_array_new ();
//    mutation->value  = g_byte_array_new ();
//    g_byte_array_append (mutation->column,(guint*)  "flow:ssh_ssl_server_info", 24);
//    g_byte_array_append (mutation->value ,(guint**) flow->ssh_ssl.server_info,  strlen(flow->ssh_ssl.server_info));
//    g_ptr_array_add (mutations, mutation);



    // src_port  c=xx
    snprintf(text[c], textSize, "%ld", ntohs(flow->src_port));
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:src_port", 13);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // dst_port  c=4
    snprintf(text[c], textSize, "%ld", ntohs(flow->dst_port));
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:dst_port", 13);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    char * proto = ipProto2Name(flow->protocol);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:protocol", 13);
    g_byte_array_append (mutation->value ,(guint*) proto,  strlen(proto));
    g_ptr_array_add (mutations, mutation);

    // bidirectional  c=6
    snprintf(text[c], textSize, "%ld", flow->bidirectional);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:bidirectional", 18);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // src_name
    snprintf(text[c], textSize, "%s", flow->src_name);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*)  "flow:src_name", 13);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // dst_name
    snprintf(text[c], textSize, "%s", flow->dst_name);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*)  "flow:dst_name", 13);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // bytes  c=7
    snprintf(text[c], textSize, "%ld", flow->bytes);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:bytes", 10);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // packets  c=8
    snprintf(text[c], textSize, "%d", flow->packets);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:packets", 12);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // payload_bytes  c=9
    snprintf(text[c], textSize, "%ld", flow->payload_bytes);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:payload_bytes", 18);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // packets_without_payload  c=10
    snprintf(text[c], textSize, "%d", flow->packets_without_payload);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:packets_without_payload", 28);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // payload_bytes_first  c=11
    snprintf(text[c], textSize, "%d", flow->payload_bytes_first);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:payload_bytes_first", 24);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // flow_duration  c=12
    snprintf(text[c], textSize, "%ld", flow->flow_duration);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:flow_duration", 18);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // src2dst_pay_bytes  c=13
    snprintf(text[c], textSize, "%ld", flow->src2dst_pay_bytes);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:src2dst_pay_bytes", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // dst2src_pay_bytes  c=14
    snprintf(text[c], textSize, "%ld", flow->dst2src_pay_bytes);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:dst2src_pay_bytes", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // src2dst_header_bytes  c=15
    snprintf(text[c], textSize, "%ld", flow->src2dst_header_bytes);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:src2dst_header_bytes", 25);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // dst2src_header_bytes  c=16
    snprintf(text[c], textSize, "%ld", flow->dst2src_header_bytes);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:dst2src_header_bytes", 25);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // src2dst_packets  c=17
    snprintf(text[c], textSize, "%d", flow->src2dst_packets);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:src2dst_packets", 20);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // dst2src_packets  c=18
    snprintf(text[c], textSize, "%d", flow->dst2src_packets);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:dst2src_packets", 20);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // src2dst_inter_time_avg  c=19
    snprintf(text[c], textSize, "%ld", flow->src2dst_inter_time_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:src2dst_inter_time_avg", 27);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // src2dst_inter_time_min  c=20
    snprintf(text[c], textSize, "%ld", flow->src2dst_inter_time_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:src2dst_inter_time_min", 27);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // src2dst_inter_time_max  c=21
    snprintf(text[c], textSize, "%ld", flow->src2dst_inter_time_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:src2dst_inter_time_max", 27);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // src2dst_inter_time_std  c=22
    snprintf(text[c], textSize, "%ld", flow->src2dst_inter_time_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:src2dst_inter_time_std", 27);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // dst2src_inter_time_avg  c=23
    snprintf(text[c], textSize, "%ld", flow->dst2src_inter_time_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:dst2src_inter_time_avg", 27);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // dst2src_inter_time_min  c=24
    snprintf(text[c], textSize, "%ld", flow->dst2src_inter_time_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:dst2src_inter_time_min", 27);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // dst2src_inter_time_max  c=25
    snprintf(text[c], textSize, "%ld", flow->dst2src_inter_time_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:dst2src_inter_time_max", 27);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // dst2src_inter_time_std  c=26
    snprintf(text[c], textSize, "%ld", flow->dst2src_inter_time_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:dst2src_inter_time_std", 27);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // src2dst_pay_bytes_avg  c=27
    snprintf(text[c], textSize, "%ld", flow->src2dst_pay_bytes_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:src2dst_pay_bytes_avg", 26);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // src2dst_pay_bytes_min  c=28
    snprintf(text[c], textSize, "%ld", flow->src2dst_pay_bytes_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:src2dst_pay_bytes_min", 26);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // src2dst_pay_bytes_max  c=29
    snprintf(text[c], textSize, "%ld", flow->src2dst_pay_bytes_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:src2dst_pay_bytes_max", 26);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // src2dst_pay_bytes_std  c=30
    snprintf(text[c], textSize, "%ld", flow->src2dst_pay_bytes_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:src2dst_pay_bytes_std", 26);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // dst2src_pay_bytes_avg  c=31
    snprintf(text[c], textSize, "%ld", flow->dst2src_pay_bytes_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:dst2src_pay_bytes_avg", 26);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // dst2src_pay_bytes_min  c=32
    snprintf(text[c], textSize, "%ld", flow->dst2src_pay_bytes_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:dst2src_pay_bytes_min", 26);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // dst2src_pay_bytes_max  c=33
    snprintf(text[c], textSize, "%ld", flow->dst2src_pay_bytes_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:dst2src_pay_bytes_max", 26);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // dst2src_pay_bytes_std  c=34
    snprintf(text[c], textSize, "%ld", flow->dst2src_pay_bytes_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:dst2src_pay_bytes_std", 26);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // dst2src_pay_bytes_rate  c=35
    snprintf(text[c], textSize, "%ld", flow->dst2src_pay_bytes_rate);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:dst2src_pay_bytes_rate", 27);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // src2dst_pay_bytes_rate  c=36
    snprintf(text[c], textSize, "%ld", flow->src2dst_pay_bytes_rate);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:src2dst_pay_bytes_rate", 27);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // dst2src_packets_rate  c=37
    snprintf(text[c], textSize, "%ld", flow->dst2src_packets_rate);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:dst2src_packets_rate", 25);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // src2dst_packets_rate  c=38
    snprintf(text[c], textSize, "%ld", flow->src2dst_packets_rate);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:src2dst_packets_rate", 25);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // inter_time_avg  c=39
    snprintf(text[c], textSize, "%ld", flow->inter_time_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:inter_time_avg", 19);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // inter_time_min  c=40
    snprintf(text[c], textSize, "%ld", flow->inter_time_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:inter_time_min", 19);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // inter_time_max  c=41
    snprintf(text[c], textSize, "%ld", flow->inter_time_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:inter_time_max", 19);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // inter_time_std  c=42
    snprintf(text[c], textSize, "%ld", flow->inter_time_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:inter_time_std", 19);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // payload_bytes_avg  c=43
    snprintf(text[c], textSize, "%ld", flow->payload_bytes_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:payload_bytes_avg", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // payload_bytes_std  c=44
    snprintf(text[c], textSize, "%ld", flow->payload_bytes_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:payload_bytes_std", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // payload_bytes_min  c=45
    snprintf(text[c], textSize, "%ld", flow->payload_bytes_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:payload_bytes_min", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // payload_bytes_max  c=46
    snprintf(text[c], textSize, "%ld", flow->payload_bytes_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:payload_bytes_max", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // src2dst_header_bytes_avg  c=47
    snprintf(text[c], textSize, "%ld", flow->src2dst_header_bytes_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:src2dst_header_bytes_avg", 29);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // src2dst_header_bytes_min  c=48
    snprintf(text[c], textSize, "%ld", flow->src2dst_header_bytes_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:src2dst_header_bytes_min", 29);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // src2dst_header_bytes_max  c=49
    snprintf(text[c], textSize, "%ld", flow->src2dst_header_bytes_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:src2dst_header_bytes_max", 29);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // src2dst_header_bytes_std  c=50
    snprintf(text[c], textSize, "%ld", flow->src2dst_header_bytes_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:src2dst_header_bytes_std", 29);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // dst2src_header_bytes_avg  c=51
    snprintf(text[c], textSize, "%ld", flow->dst2src_header_bytes_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:dst2src_header_bytes_avg", 29);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // dst2src_header_bytes_min  c=52
    snprintf(text[c], textSize, "%ld", flow->dst2src_header_bytes_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:dst2src_header_bytes_min", 29);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // dst2src_header_bytes_max  c=53
    snprintf(text[c], textSize, "%ld", flow->dst2src_header_bytes_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:dst2src_header_bytes_max", 29);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // dst2src_header_bytes_std  c=54
    snprintf(text[c], textSize, "%ld", flow->dst2src_header_bytes_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:dst2src_header_bytes_std", 29);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // packets_syn  c=55
    snprintf(text[c], textSize, "%d", flow->packets_syn);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:packets_syn", 16);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // packets_ack  c=56
    snprintf(text[c], textSize, "%d", flow->packets_ack);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:packets_ack", 16);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // packets_fin  c=57
    snprintf(text[c], textSize, "%d", flow->packets_fin);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:packets_fin", 16);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // packets_rst  c=58
    snprintf(text[c], textSize, "%d", flow->packets_rst);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:packets_rst", 16);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // packets_psh  c=59
    snprintf(text[c], textSize, "%d", flow->packets_psh);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:packets_psh", 16);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // packets_urg  c=60
    snprintf(text[c], textSize, "%d", flow->packets_urg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:packets_urg", 16);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // tcp_retransmissions  c=61
    snprintf(text[c], textSize, "%d", flow->tcp_retransmissions);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:tcp_retransmissions", 24);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // payload_size_variation  c=62
    snprintf(text[c], textSize, "%d", flow->payload_size_variation);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:payload_size_variation", 27);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_number_of_contacts  c=66
    snprintf(text[c], textSize, "%d", flow->C_number_of_contacts);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_number_of_contacts", 25);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_src2dst_pay_bytes_avg  c=67
    snprintf(text[c], textSize, "%ld", flow->C_src2dst_pay_bytes_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_src2dst_pay_bytes_avg", 28);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_src2dst_pay_bytes_min  c=68
    snprintf(text[c], textSize, "%ld", flow->C_src2dst_pay_bytes_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_src2dst_pay_bytes_min", 28);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_src2dst_pay_bytes_max  c=69
    snprintf(text[c], textSize, "%ld", flow->C_src2dst_pay_bytes_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_src2dst_pay_bytes_max", 28);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_src2dst_pay_bytes_std  c=70
    snprintf(text[c], textSize, "%ld", flow->C_src2dst_pay_bytes_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_src2dst_pay_bytes_std", 28);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_src2dst_header_bytes_avg  c=71
    snprintf(text[c], textSize, "%ld", flow->C_src2dst_header_bytes_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_src2dst_header_bytes_avg", 31);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_src2dst_header_bytes_min  c=72
    snprintf(text[c], textSize, "%ld", flow->C_src2dst_header_bytes_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_src2dst_header_bytes_min", 31);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_src2dst_header_bytes_max  c=73
    snprintf(text[c], textSize, "%ld", flow->C_src2dst_header_bytes_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_src2dst_header_bytes_max", 31);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_src2dst_header_bytes_std  c=74
    snprintf(text[c], textSize, "%ld", flow->C_src2dst_header_bytes_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_src2dst_header_bytes_std", 31);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_src2dst_packets_avg  c=75
    snprintf(text[c], textSize, "%ld", flow->C_src2dst_packets_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_src2dst_packets_avg", 26);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_src2dst_packets_min  c=76
    snprintf(text[c], textSize, "%ld", flow->C_src2dst_packets_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_src2dst_packets_min", 26);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_src2dst_packets_max  c=77
    snprintf(text[c], textSize, "%ld", flow->C_src2dst_packets_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_src2dst_packets_max", 26);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_src2dst_packets_std  c=78
    snprintf(text[c], textSize, "%ld", flow->C_src2dst_packets_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_src2dst_packets_std", 26);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_dst2src_pay_bytes_avg  c=79
    snprintf(text[c], textSize, "%ld", flow->C_dst2src_pay_bytes_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_dst2src_pay_bytes_avg", 28);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_dst2src_pay_bytes_min  c=80
    snprintf(text[c], textSize, "%ld", flow->C_dst2src_pay_bytes_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_dst2src_pay_bytes_min", 28);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_dst2src_pay_bytes_max  c=81
    snprintf(text[c], textSize, "%ld", flow->C_dst2src_pay_bytes_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_dst2src_pay_bytes_max", 28);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_dst2src_pay_bytes_std  c=82
    snprintf(text[c], textSize, "%ld", flow->C_dst2src_pay_bytes_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_dst2src_pay_bytes_std", 28);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_dst2src_header_bytes_avg  c=83
    snprintf(text[c], textSize, "%ld", flow->C_dst2src_header_bytes_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_dst2src_header_bytes_avg", 31);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_dst2src_header_bytes_min  c=84
    snprintf(text[c], textSize, "%ld", flow->C_dst2src_header_bytes_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_dst2src_header_bytes_min", 31);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_dst2src_header_bytes_max  c=85
    snprintf(text[c], textSize, "%ld", flow->C_dst2src_header_bytes_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_dst2src_header_bytes_max", 31);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_dst2src_header_bytes_std  c=86
    snprintf(text[c], textSize, "%ld", flow->C_dst2src_header_bytes_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_dst2src_header_bytes_std", 31);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_dst2src_packets_avg  c=87
    snprintf(text[c], textSize, "%ld", flow->C_dst2src_packets_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_dst2src_packets_avg", 26);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_dst2src_packets_min  c=88
    snprintf(text[c], textSize, "%ld", flow->C_dst2src_packets_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_dst2src_packets_min", 26);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_dst2src_packets_max  c=89
    snprintf(text[c], textSize, "%ld", flow->C_dst2src_packets_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_dst2src_packets_max", 26);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_dst2src_packets_std  c=90
    snprintf(text[c], textSize, "%ld", flow->C_dst2src_packets_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_dst2src_packets_std", 26);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_packets_syn_avg  c=91
    snprintf(text[c], textSize, "%ld", flow->C_packets_syn_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_packets_syn_avg", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_packets_syn_min  c=92
    snprintf(text[c], textSize, "%ld", flow->C_packets_syn_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_packets_syn_min", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_packets_syn_max  c=93
    snprintf(text[c], textSize, "%ld", flow->C_packets_syn_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_packets_syn_max", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_packets_syn_std  c=94
    snprintf(text[c], textSize, "%ld", flow->C_packets_syn_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_packets_syn_std", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_packets_ack_avg  c=95
    snprintf(text[c], textSize, "%ld", flow->C_packets_ack_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_packets_ack_avg", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_packets_ack_min  c=96
    snprintf(text[c], textSize, "%ld", flow->C_packets_ack_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_packets_ack_min", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_packets_ack_max  c=97
    snprintf(text[c], textSize, "%ld", flow->C_packets_ack_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_packets_ack_max", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_packets_ack_std  c=98
    snprintf(text[c], textSize, "%ld", flow->C_packets_ack_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_packets_ack_std", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_packets_fin_avg  c=99
    snprintf(text[c], textSize, "%ld", flow->C_packets_fin_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_packets_fin_avg", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_packets_fin_min  c=100
    snprintf(text[c], textSize, "%ld", flow->C_packets_fin_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_packets_fin_min", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_packets_fin_max  c=101
    snprintf(text[c], textSize, "%ld", flow->C_packets_fin_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_packets_fin_max", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_packets_fin_std  c=102
    snprintf(text[c], textSize, "%ld", flow->C_packets_fin_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_packets_fin_std", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_packets_rst_avg  c=103
    snprintf(text[c], textSize, "%ld", flow->C_packets_rst_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_packets_rst_avg", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_packets_rst_min  c=104
    snprintf(text[c], textSize, "%ld", flow->C_packets_rst_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_packets_rst_min", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_packets_rst_max  c=105
    snprintf(text[c], textSize, "%ld", flow->C_packets_rst_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_packets_rst_max", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_packets_rst_std  c=106
    snprintf(text[c], textSize, "%ld", flow->C_packets_rst_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_packets_rst_std", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_packets_psh_avg  c=107
    snprintf(text[c], textSize, "%ld", flow->C_packets_psh_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_packets_psh_avg", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_packets_psh_min  c=108
    snprintf(text[c], textSize, "%ld", flow->C_packets_psh_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_packets_psh_min", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_packets_psh_max  c=109
    snprintf(text[c], textSize, "%ld", flow->C_packets_psh_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_packets_psh_max", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_packets_psh_std  c=110
    snprintf(text[c], textSize, "%ld", flow->C_packets_psh_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_packets_psh_std", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_packets_urg_avg  c=111
    snprintf(text[c], textSize, "%ld", flow->C_packets_urg_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_packets_urg_avg", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_packets_urg_min  c=112
    snprintf(text[c], textSize, "%ld", flow->C_packets_urg_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_packets_urg_min", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_packets_urg_max  c=113
    snprintf(text[c], textSize, "%ld", flow->C_packets_urg_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_packets_urg_max", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_packets_urg_std  c=114
    snprintf(text[c], textSize, "%ld", flow->C_packets_urg_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_packets_urg_std", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_tcp_retransmissions_avg  c=115
    snprintf(text[c], textSize, "%ld", flow->C_tcp_retransmissions_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_tcp_retransmissions_avg", 30);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_tcp_retransmissions_min  c=116
    snprintf(text[c], textSize, "%ld", flow->C_tcp_retransmissions_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_tcp_retransmissions_min", 30);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_tcp_retransmissions_max  c=117
    snprintf(text[c], textSize, "%ld", flow->C_tcp_retransmissions_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_tcp_retransmissions_max", 30);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_tcp_retransmissions_std  c=118
    snprintf(text[c], textSize, "%ld", flow->C_tcp_retransmissions_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_tcp_retransmissions_std", 30);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_dst2src_pay_bytes_rate_avg  c=119
    snprintf(text[c], textSize, "%ld", flow->C_dst2src_pay_bytes_rate_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_dst2src_pay_bytes_rate_avg", 33);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_dst2src_pay_bytes_rate_min  c=120
    snprintf(text[c], textSize, "%ld", flow->C_dst2src_pay_bytes_rate_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_dst2src_pay_bytes_rate_min", 33);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_dst2src_pay_bytes_rate_max  c=121
    snprintf(text[c], textSize, "%ld", flow->C_dst2src_pay_bytes_rate_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_dst2src_pay_bytes_rate_max", 33);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_dst2src_pay_bytes_rate_std  c=122
    snprintf(text[c], textSize, "%ld", flow->C_dst2src_pay_bytes_rate_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_dst2src_pay_bytes_rate_std", 33);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_src2dst_pay_bytes_rate_avg  c=123
    snprintf(text[c], textSize, "%ld", flow->C_src2dst_pay_bytes_rate_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_src2dst_pay_bytes_rate_avg", 33);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_src2dst_pay_bytes_rate_min  c=124
    snprintf(text[c], textSize, "%ld", flow->C_src2dst_pay_bytes_rate_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_src2dst_pay_bytes_rate_min", 33);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_src2dst_pay_bytes_rate_max  c=125
    snprintf(text[c], textSize, "%ld", flow->C_src2dst_pay_bytes_rate_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_src2dst_pay_bytes_rate_max", 33);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_src2dst_pay_bytes_rate_std  c=126
    snprintf(text[c], textSize, "%ld", flow->C_src2dst_pay_bytes_rate_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_src2dst_pay_bytes_rate_std", 33);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_dst2src_packets_rate_avg  c=127
    snprintf(text[c], textSize, "%ld", flow->C_dst2src_packets_rate_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_dst2src_packets_rate_avg", 31);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_dst2src_packets_rate_min  c=128
    snprintf(text[c], textSize, "%ld", flow->C_dst2src_packets_rate_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_dst2src_packets_rate_min", 31);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_dst2src_packets_rate_max  c=129
    snprintf(text[c], textSize, "%ld", flow->C_dst2src_packets_rate_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_dst2src_packets_rate_max", 31);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_dst2src_packets_rate_std  c=130
    snprintf(text[c], textSize, "%ld", flow->C_dst2src_packets_rate_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_dst2src_packets_rate_std", 31);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_src2dst_packets_rate_avg  c=131
    snprintf(text[c], textSize, "%ld", flow->C_src2dst_packets_rate_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_src2dst_packets_rate_avg", 31);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_src2dst_packets_rate_min  c=132
    snprintf(text[c], textSize, "%ld", flow->C_src2dst_packets_rate_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_src2dst_packets_rate_min", 31);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_src2dst_packets_rate_max  c=133
    snprintf(text[c], textSize, "%ld", flow->C_src2dst_packets_rate_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_src2dst_packets_rate_max", 31);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_src2dst_packets_rate_std  c=134
    snprintf(text[c], textSize, "%ld", flow->C_src2dst_packets_rate_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_src2dst_packets_rate_std", 31);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_duration_avg  c=135
    snprintf(text[c], textSize, "%ld", flow->C_duration_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_duration_avg", 19);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_duration_min  c=136
    snprintf(text[c], textSize, "%ld", flow->C_duration_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_duration_min", 19);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_duration_max  c=137
    snprintf(text[c], textSize, "%ld", flow->C_duration_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_duration_max", 19);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_duration_std  c=138
    snprintf(text[c], textSize, "%ld", flow->C_duration_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_duration_std", 19);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_idletime_avg  c=139
    snprintf(text[c], textSize, "%ld", flow->C_idletime_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_idletime_avg", 19);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_idletime_min  c=140
    snprintf(text[c], textSize, "%ld", flow->C_idletime_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_idletime_min", 19);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_idletime_max  c=141
    snprintf(text[c], textSize, "%ld", flow->C_idletime_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_idletime_max", 19);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_idletime_std  c=142
    snprintf(text[c], textSize, "%ld", flow->C_idletime_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_idletime_std", 19);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // flow_use_time  c=143
    snprintf(text[c], textSize, "%ld", flow->flow_use_time);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:flow_use_time", 18);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // flow_idle_time  c=144
    snprintf(text[c], textSize, "%ld", flow->flow_idle_time);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:flow_idle_time", 19);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // response_rel_time  c=145
    snprintf(text[c], textSize, "%d", flow->response_rel_time);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:response_rel_time", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // detection_completed
    snprintf(text[c], textSize, "%d", flow->detection_completed);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:detection_completed", 24);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_inter_start_time_avg  c=145
    snprintf(text[c], textSize, "%d", flow->C_inter_start_time_avg);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_inter_start_time_avg", 27);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_inter_start_time_min  c=146
    snprintf(text[c], textSize, "%d", flow->C_inter_start_time_min);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_inter_start_time_min", 27);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_inter_start_time_max  c=147
    snprintf(text[c], textSize, "%d", flow->C_inter_start_time_max);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_inter_start_time_max", 27);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // C_inter_start_time_std  c=148
    snprintf(text[c], textSize, "%d", flow->C_inter_start_time_std);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:C_inter_start_time_std", 27);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;



    // detected_protocol
    if(flow->detected_protocol.master_protocol && flow->detected_protocol.app_protocol!=NULL && flow->detected_protocol.app_protocol!=0) {
        char buf[64];

        snprintf(text[c], textSize, "%u.%u/%s",
                flow->detected_protocol.master_protocol, flow->detected_protocol.app_protocol,
                ndpi_protocol2name(ndpi_info.ndpi_struct,flow->detected_protocol, buf, sizeof(buf)));

        snprintf(text[c+1], textSize,"%s", ndpi_get_proto_breed_name(ndpi_info.ndpi_struct,
                ndpi_get_proto_breed(ndpi_info.ndpi_struct, flow->detected_protocol.app_protocol)));
    } else if(flow->detected_protocol.master_protocol){
        snprintf(text[c], textSize, "%u/%s",
                flow->detected_protocol.master_protocol,
                ndpi_get_proto_name(ndpi_info.ndpi_struct, flow->detected_protocol.master_protocol));

        snprintf(text[c+1], textSize, "%s", ndpi_get_proto_breed_name(ndpi_info.ndpi_struct,
                ndpi_get_proto_breed(ndpi_info.ndpi_struct, flow->detected_protocol.master_protocol)));
    } else {
        snprintf(text[c], textSize, "%u/%s",
                flow->detected_protocol.app_protocol,
                ndpi_get_proto_name(ndpi_info.ndpi_struct, flow->detected_protocol.app_protocol));


        snprintf(text[c+1], textSize, "%s", ndpi_get_proto_breed_name(ndpi_info.ndpi_struct,
                ndpi_get_proto_breed(ndpi_info.ndpi_struct, flow->detected_protocol.app_protocol)));
    }


    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:detected_protocol", 22);
    g_byte_array_append (mutation->value ,(guint**) text[c],  strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;


    // ndpi_risk
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:ndpi_risk", 14);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;

    // detected_os

    if(flow->ndpi_flow!=NULL && flow->ndpi_flow->detected_os!=NULL){
        snprintf(text[c], textSize, "%s", flow->ndpi_flow->detected_os);
    }else
        snprintf(text[c], textSize, "");

    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:detected_os", 16);
    g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
    g_ptr_array_add (mutations, mutation);
    c++;


    // Packets
    int i;
    for(i=0;i<flow->packets && i<sizeof(flow->inter_time);i++)
    {
        char itime[10];
        char psize[10];
        char hsize[10];
        char direction[10];
        char itimename[25];
        char psizename[30];
        char hsizename[30];
        char directionname[25];
        snprintf(itime, 10, "%d", flow->inter_time[i]);
        snprintf(psize, 10, "%d", flow->packet_pay_size[i]);
        snprintf(hsize, 10, "%d", flow->packet_header_size[i]);
        snprintf(direction, 10, "%d", flow->direction[i]);
        snprintf(itimename, 25, "flow:inter_time-%d", i);
        snprintf(psizename, 30, "flow:packet_pay_size-%d", i);
        snprintf(hsizename, 30, "flow:packet_header_size-%d", i);
        snprintf(directionname, 25, "flow:packet_direction-%d", i);

        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint**) itimename, strlen(itimename));
        g_byte_array_append (mutation->value ,(guint**) itime,  strlen(itime));
        g_ptr_array_add (mutations, mutation);

        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint**) psizename, strlen(psizename));
        g_byte_array_append (mutation->value ,(guint**) psize,  strlen(psize));
        g_ptr_array_add (mutations, mutation);

        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint**) hsizename, strlen(hsizename));
        g_byte_array_append (mutation->value ,(guint**) hsize,  strlen(hsize));
        g_ptr_array_add (mutations, mutation);

        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint**) directionname, strlen(directionname));
        g_byte_array_append (mutation->value ,(guint**) direction,  strlen(direction));
        g_ptr_array_add (mutations, mutation);
    }

    if(flow->event!=NULL) {
        snprintf(text[c], textSize, "%d", ntohl(flow->event->sensor_id));
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "event:sensor_id", 15);
        g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
        g_ptr_array_add (mutations, mutation);
        c++;

        snprintf(text[c], textSize, "%u", ntohl(flow->event->event_id));
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "event:event_id", 14);
        g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
        g_ptr_array_add (mutations, mutation);
        c++;

        snprintf(text[c], textSize, "%u", ntohl(flow->event->event_second));
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "event:event_second", 18);
        g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
        g_ptr_array_add (mutations, mutation);
        c++;

        snprintf(text[c], textSize, "%u", ntohl(flow->event->event_microsecond));
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "event:event_microsecond", 23);
        g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
        g_ptr_array_add (mutations, mutation);
        c++;

        snprintf(text[c], textSize, "%u", ntohl(flow->event->signature_id));
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "event:signature_id", 18);
        g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
        g_ptr_array_add (mutations, mutation);
        c++;

        snprintf(text[c], textSize, "%u", ntohl(flow->event->generator_id));
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "event:generator_id", 18);
        g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
        g_ptr_array_add (mutations, mutation);
        c++;

        snprintf(text[c], textSize, "%u", ntohl(flow->event->classification_id));
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "event:classification_id", 23);
        g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
        g_ptr_array_add (mutations, mutation);
        c++;

        snprintf(text[c], textSize, "%u", ntohl(flow->event->priority_id));
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "event:priority_id", 17);
        g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
        g_ptr_array_add (mutations, mutation);
        c++;


    }



    if(flow->protocol == IPPROTO_UDP && flow->detected_protocol.master_protocol == NDPI_PROTOCOL_DNS && flow->ndpi_flow!=NULL) {
        // for debug: raise(SIGINT);
        // dns.num_queries
        snprintf(text[c], textSize, "%d", flow->ndpi_flow->protos.dns.num_queries);
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "flow:dns_num_queries", 20);
        g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
        g_ptr_array_add (mutations, mutation);
        c++;

        // dns.num_answers
        snprintf(text[c], textSize, "%d", flow->ndpi_flow->protos.dns.num_answers);
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "flow:dns_num_answers", 20);
        g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
        g_ptr_array_add (mutations, mutation);
        c++;

        // dns.reply_code
        snprintf(text[c], textSize, "%d", flow->ndpi_flow->protos.dns.reply_code);
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "flow:dns_reply_code", 19);
        g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
        g_ptr_array_add (mutations, mutation);
        c++;

        // dns.query_type
        snprintf(text[c], textSize, "%d", flow->ndpi_flow->protos.dns.query_type);
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "flow:dns_query_type", 19);
        g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
        g_ptr_array_add (mutations, mutation);
        c++;

        // dns.query_class
        snprintf(text[c], textSize, "%d", flow->ndpi_flow->protos.dns.query_class);
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "flow:dns_query_class", 20);
        g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
        g_ptr_array_add (mutations, mutation);
        c++;

        // dns.rsp_type
        snprintf(text[c], textSize, "%d", flow->ndpi_flow->protos.dns.rsp_type);
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "flow:dns_rsp_type", 17);
        g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
        g_ptr_array_add (mutations, mutation);
        c++;
    }

    if(flow->protocol == IPPROTO_TCP && flow->detected_protocol.app_protocol == NDPI_PROTOCOL_HTTP  && flow->ndpi_flow!=NULL) {

        // http.method
        snprintf(text[c], textSize, "%d", flow->ndpi_flow->http.method);
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "flow:http_method", 16);
        g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
        g_ptr_array_add (mutations, mutation);
        c++;

        // http.url
        if(flow->ndpi_flow->http.url != NULL)
        {
            snprintf(text[c], textSize, "%s", flow->ndpi_flow->http.url);
            mutation = g_object_new (TYPE_MUTATION, NULL);
            mutation->column = g_byte_array_new ();
            mutation->value  = g_byte_array_new ();
            g_byte_array_append (mutation->column,(guint*) "flow:http_url", 13);
            g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
            g_ptr_array_add (mutations, mutation);
            c++;
        }

        // http.content_type
        if(flow->ndpi_flow->http.content_type != NULL)
        {
            snprintf(text[c], textSize, "%s", flow->ndpi_flow->http.content_type);
            mutation = g_object_new (TYPE_MUTATION, NULL);
            mutation->column = g_byte_array_new ();
            mutation->value  = g_byte_array_new ();
            g_byte_array_append (mutation->column,(guint*) "flow:http_content_type", 22);
            g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
            g_ptr_array_add (mutations, mutation);
            c++;
        }

        // http.num_request_headers
        snprintf(text[c], textSize, "%d", flow->ndpi_flow->http.num_request_headers);
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "flow:http_num_request_headers", 29);
        g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
        g_ptr_array_add (mutations, mutation);
        c++;

        // http.num_response_headers
        snprintf(text[c], textSize, "%d", flow->ndpi_flow->http.num_response_headers);
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "flow:http_num_response_headers", 30);
        g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
        g_ptr_array_add (mutations, mutation);
        c++;

        // http.request_version
        snprintf(text[c], textSize, "%d", flow->ndpi_flow->http.request_version);
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "flow:http_request_version", 25);
        g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
        g_ptr_array_add (mutations, mutation);
        c++;

        // http.response_status_code
        if(flow->ndpi_flow->http.response_status_code != NULL) {
            snprintf(text[c], textSize, "%s", flow->ndpi_flow->http.response_status_code);
            mutation = g_object_new (TYPE_MUTATION, NULL);
            mutation->column = g_byte_array_new ();
            mutation->value  = g_byte_array_new ();
            g_byte_array_append (mutation->column,(guint*) "flow:http_response_status_code", 30);
            g_byte_array_append (mutation->value ,(guint**) text[c],3);
            g_ptr_array_add (mutations, mutation);
            c++;
        }
    }

    mutation=NULL;
}


/*
 * Function: PreprocFunction(Packet *)
 *
 * Purpose: Perform the preprocessor's intended function.  This can be
 *          simple (statistics collection) or complex (IP defragmentation)
 *          as you like.  Try not to destroy the performance of the whole
 *          system by trying to do too much....
 *
 * Arguments: p => pointer to the current packet data struct 
 *
 * Returns: void function
 */
static void Hogzilla(Packet *p, void *event, uint32_t event_type, void *arg)
{
    struct ndpi_flow_info *flow;

    // Comment it in english:
    // Processar na nDPI
    //    . lá na nDPI, quando ocorrer uma das abaixo, o flow deve ser salvo no HBASE
    //       i  ) Conexão terminou
    //       ii ) Atingiu 500 pacotes no fluxo
    //       iii) A conexão ficou IDLE por mais de HOGZILLA_MAX_IDLE_TIME

    //LogMessage("DEBUG => [Hogzilla] Line %d in file %s\n", __LINE__, __FILE__);

    if(p)
    {
        flow=packet_processing_by_pcap( (const struct pcap_pkthdr *) p->pkth, p->pkt);
        if(flow != NULL && event!=NULL && flow->event==NULL)
        {
           flow->event= (struct Unified2EventCommon*)HzAlloc(sizeof(Unified2EventCommon));
           memcpy(flow->event, event, sizeof(Unified2EventCommon));
        }
    }

    // Deixe aqui por enquanto, pode ser necessário no futuro.
    //    if(p)
    //    {
    //        if(p->packet_flags & PKT_REBUILT_STREAM)
    //        {
    //            HogzillaStream(p, event, event_type, arg);
    //        }
    //        else
    //        {
    //            HogzillaSingle(p, event, event_type, arg);
    //        }
    //    }
    //LogMessage("DEBUG => [Hogzilla] Line %d in file %s\n", __LINE__, __FILE__);
}
