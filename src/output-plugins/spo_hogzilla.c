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
 * TODO: HZ
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


#define ALARMS_RUN                      30 /* 30secs */
#define HOGZILLA_MAX_NDPI_FLOWS         500000
#define HOGZILLA_MAX_NDPI_PKT_PER_FLOW  500
#define HOGZILLA_MAX_IDLE_TIME          30000 /* 1000=1sec */
#define IDLE_SCAN_PERIOD                1000   /* 1000=1sec */
//#define NUM_ROOTS                 512
#define NUM_ROOTS                       1
#define MAX_EXTRA_PACKETS_TO_CHECK      7
#define TICK_RESOLUTION                 1000
#define GTP_U_V1_PORT                   2152
#define IDLE_SCAN_BUDGET                4096

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



/* If you need to instantiate the plugin's data structure, do it here */
HogzillaData *hogzilla_ptr;
HogzillaHBase *hbase;
struct reader_hogzilla ndpi_info;

static u_int8_t undetected_flows_deleted = 0;
static u_int32_t size_id_struct = 0;		//< ID tracking structure size
static u_int32_t size_flow_struct = 0;
static u_int16_t decode_tunnels = 0;

// YYY
GHashTable * attributes;
Text * table ;


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

    size_id_struct   = ndpi_detection_get_sizeof_ndpi_id_struct();
    size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();
    //LogMessage("DEBUG => [Hogzilla] Line %d in file %s\n", __LINE__, __FILE__);
}

void signal_callback_handler(int signum){

        printf("Caught signal SIGPIPE %d\n",signum);
}

void check_hbase_open(){
    while(!thrift_transport_is_open (hbase->transport)){
        closeHBase();
        connectHBase();
    }
}

void scan_idle_flows(){
    if(ndpi_info.last_idle_scan_time + IDLE_SCAN_PERIOD < ndpi_info.last_time) {
            /* scan for idle flows */
            ndpi_twalk(ndpi_info.ndpi_flows_root[ndpi_info.idle_scan_idx], node_idle_scan_walker,NULL);

            HogzillaSaveFlows();

            /* remove idle flows (unfortunately we cannot do this inline) */
            while (ndpi_info.num_idle_flows > 0){
                ndpi_tdelete(ndpi_info.idle_flows[--ndpi_info.num_idle_flows], &ndpi_info.ndpi_flows_root[ndpi_info.idle_scan_idx], node_cmp);
                free(ndpi_info.idle_flows[ndpi_info.num_idle_flows]);
            }
            // LogMessage("DEBUG => [Hogzilla] Flows in memory: %d \n", ndpi_info.ndpi_flow_count);
            if(++ndpi_info.idle_scan_idx == NUM_ROOTS) ndpi_info.idle_scan_idx = 0;
            ndpi_info.last_idle_scan_time = ndpi_info.last_time;
     }
}

void my_alarms(int sig) {

    scan_idle_flows();

    alarm(ALARMS_RUN);
    signal(SIGALRM, my_alarms);
}


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

    /* Start timers using ALARMS */
    signal(SIGALRM, my_alarms);  alarm(ALARMS_RUN);
}

/*
 * Function: ParseHogzillaArgs(char *)
 *
 * Purpose: Process positional args, if any.  Syntax is:
 * TODO HZ
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
    data = (HogzillaData *) SnortAlloc(sizeof(HogzillaData));

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


// flow tracking
typedef struct ndpi_flow_info {
    u_int32_t hashval;
    u_int32_t src_ip;
    u_int32_t dst_ip;
    u_int16_t src_port;
    u_int16_t dst_port;
    u_int8_t  detection_completed, protocol, bidirectional, check_extra_packets;
    u_int16_t vlan_id;
    struct ndpi_flow_struct *ndpi_flow;
    char src_name[32], dst_name[32];
    u_int8_t ip_version;

    u_int64_t last_seen;
    u_int64_t src2dst_bytes, dst2src_bytes;
    u_int32_t src2dst_packets, dst2src_packets;

    u_int64_t bytes;
    u_int32_t packets;

    u_int32_t max_packet_size;
    u_int32_t min_packet_size;
    u_int32_t avg_packet_size;
    u_int64_t avg_inter_time;
    u_int64_t payload_bytes;
    u_int32_t payload_first_size;
    u_int32_t payload_avg_size;
    u_int32_t payload_min_size;
    u_int32_t payload_max_size;
    u_int32_t packets_without_payload;
    u_int64_t flow_duration;
    u_int64_t first_seen;
    u_int32_t inter_time [HOGZILLA_MAX_NDPI_PKT_PER_FLOW];
    u_int64_t packet_size[HOGZILLA_MAX_NDPI_PKT_PER_FLOW];

    Unified2EventCommon *event;

    // result only, not used for flow identification
    ndpi_protocol detected_protocol;

    char info[96];
    char host_server_name[192];
    char bittorent_hash[41];

    struct {
      char client_info[48], server_info[48];
    } ssh_ssl;

    void *src_id, *dst_id;

    u_int8_t saved;
    u_int8_t fin_stage; /*1: 1st FIN, 2: FIN reply */
} ndpi_flow_t;

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
    // raise(SIGINT);
    Mutation *mutation = (Mutation *) data;
    g_byte_array_free(mutation->column,TRUE);
    g_byte_array_free(mutation->value,TRUE);
    g_object_unref (data);
    data = NULL;
    mutation = NULL;
}
/* ***************************************************** */
void cleanBatchMutation(gpointer data, gpointer b) {
    BatchMutation *bm = (BatchMutation *) data;
    g_byte_array_free(bm->row,TRUE);
    g_ptr_array_foreach(bm->mutations,cleanMutation,(gpointer) NULL);
    g_ptr_array_free(bm->mutations,TRUE);
    g_object_unref (data);
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
            sprintf(str, "%lld.%lld", flow->first_seen,flow->src_ip) ;
            g_byte_array_append (rowMutation->row,(guint*) str,  strlen(str));

            rowMutation->mutations  = g_ptr_array_new ();
            Hogzilla_mutations(flow,rowMutation->mutations);

            g_ptr_array_add (batchRows, rowMutation);
            rowMutation = NULL;
            flow->saved = 1;

            //printFlow(flow);
        }

        free_ndpi_flow(flow);
        ndpi_info.ndpi_flow_count--;
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

    fprintf(out, "[%u pkts/%llu bytes ", flow->src2dst_packets, (long long unsigned int) flow->src2dst_bytes);
    fprintf(out, "%s %u pkts/%llu bytes]",
        (flow->dst2src_packets > 0) ? "<->" : "->",
        flow->dst2src_packets, (long long unsigned int) flow->dst2src_bytes);

    if(flow->host_server_name[0] != '\0') fprintf(out, "[Host: %s]", flow->host_server_name);
    if(flow->info[0] != '\0') fprintf(out, "[%s]", flow->info);

    if(flow->ssh_ssl.client_info[0] != '\0') fprintf(out, "[client: %s]", flow->ssh_ssl.client_info);
    if(flow->ssh_ssl.server_info[0] != '\0') fprintf(out, "[server: %s]", flow->ssh_ssl.server_info);
    if(flow->bittorent_hash[0] != '\0') fprintf(out, "[BT Hash: %s]", flow->bittorent_hash);

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

    GHashTable * attributes = g_hash_table_new(g_str_hash, g_str_equal);
    GPtrArray * mutations;
    mutations = g_ptr_array_new ();

    Hogzilla_mutations(flow,mutations);

    //TODO HZ: find a better flow ID
    sprintf(str, "%lld.%lld", flow->first_seen,flow->src_ip) ;
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
}
/* ***************************************************** */
static void node_idle_scan_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
    struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;

    //  idle connections, Save in HBase and remove
    if(ndpi_info.num_idle_flows == IDLE_SCAN_BUDGET) /* TODO optimise with a budget-based walk */
        return;

    if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
        if(flow->last_seen + HOGZILLA_MAX_IDLE_TIME < ndpi_info.last_time) {

            /* update stats */
            node_proto_guess_walker(node, which, depth, user_data);

            if((flow->detected_protocol.master_protocol == NDPI_PROTOCOL_UNKNOWN) && !undetected_flows_deleted)
                undetected_flows_deleted = 1;

            /* adding to a queue (we can't delete it from the tree inline ) */
            ndpi_info.idle_flows[ndpi_info.num_idle_flows++] = flow;
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

    //  if(0)
    //    printf("[NDPI] [%u][%u:%u <-> %u:%u]\n",
    //     iph->protocol, lower_ip, ntohs(lower_port), upper_ip, ntohs(upper_port));

    idx = hashval % NUM_ROOTS;
    ret = ndpi_tfind(&flow, &ndpi_info.ndpi_flows_root[idx], node_cmp);

    if(ret == NULL) {
        if(ndpi_info.ndpi_flow_count == HOGZILLA_MAX_NDPI_FLOWS) {
            LogMessage("ERROR => [Hogzilla] maximum flow count (%u) has been exceeded\n", HOGZILLA_MAX_NDPI_FLOWS);
            exit(-1);
        } else {
            struct ndpi_flow_info *newflow = (struct ndpi_flow_info*)malloc(sizeof(struct ndpi_flow_info));

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
            newflow->min_packet_size=999999;
            newflow->payload_min_size=999999;
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

            if((newflow->ndpi_flow = malloc(size_flow_struct)) == NULL) {
                LogMessage("ERROR => [Hogzilla] %s(2): not enough memory\n", __FUNCTION__);
                free(newflow);
                return(NULL);
            }

            memset(newflow->ndpi_flow, 0, size_flow_struct);

            if((newflow->src_id = malloc(size_id_struct)) == NULL) {
                LogMessage("ERROR => [Hogzilla] %s(3): not enough memory\n", __FUNCTION__);
                free(newflow);
                return(NULL);
            }
            memset(newflow->src_id, 0, size_id_struct);

            if((newflow->dst_id = malloc(size_id_struct)) == NULL) {
                LogMessage("ERROR => [Hogzilla] %s(4): not enough memory\n", __FUNCTION__);
                free(newflow);
                return(NULL);
            }
            memset(newflow->dst_id, 0, size_id_struct);

            ndpi_tsearch(newflow, &ndpi_info.ndpi_flows_root[idx], node_cmp); /* Add */
            ndpi_info.ndpi_flow_count++;

            *src = newflow->src_id, *dst = newflow->dst_id;

            // printFlow(thread_id, newflow);

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
static void updateFlowFeatures(struct ndpi_flow_info *flow,
        const u_int64_t time,
        u_int16_t vlan_id,
        const struct ndpi_iphdr *iph,
        struct ndpi_ipv6hdr *iph6,
        u_int16_t ip_offset,
        u_int16_t ipsize,
        u_int16_t rawsize,
        u_int8_t src_to_dst_direction) {

    if(flow->packets==0)
        flow->last_seen = time;

    if(flow->packets<HOGZILLA_MAX_NDPI_PKT_PER_FLOW)
    {
        flow->inter_time[flow->packets] = time - flow->last_seen;
        flow->packet_size[flow->packets]=rawsize;
        flow->avg_packet_size  = (flow->avg_packet_size*flow->packets  + rawsize)/(flow->packets+1);
        flow->avg_inter_time  = (flow->avg_inter_time*flow->packets  + (time - flow->last_seen))/(flow->packets+1);
        flow->payload_avg_size = (flow->payload_avg_size*flow->packets + ipsize )/(flow->packets+1);
    }
    flow->packets++, flow->bytes += rawsize;
    flow->last_seen = time;

    if(flow->min_packet_size>rawsize)
        flow->min_packet_size = rawsize;

    if(flow->max_packet_size<rawsize)
        flow->max_packet_size = rawsize;

    if(flow->payload_min_size>ipsize)
        flow->payload_min_size = ipsize;

    if(flow->payload_max_size<ipsize)
        flow->payload_max_size = ipsize;

    flow->payload_bytes += ipsize;
    if(flow->packets==1)
    {
        flow->payload_first_size = ipsize;
        flow->first_seen=time;
    }

    if(src_to_dst_direction)
      flow->src2dst_packets++, flow->src2dst_bytes += rawsize;
    else
      flow->dst2src_packets++, flow->dst2src_bytes += rawsize;

    if(ipsize==0)
        flow->packets_without_payload++;

    flow->flow_duration = time - flow->first_seen;
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
        // printf("\nWARNING: timestamp bug in the pcap file (ts delta: %llu, repairing)\n", ndpi_info.last_time - time);
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

    snprintf(flow->host_server_name, sizeof(flow->host_server_name), "%s",
            flow->ndpi_flow->host_server_name);

    /* BITTORRENT */
    if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_BITTORRENT) {
        int i, j, n = 0;

        for(i=0, j = 0; j < sizeof(flow->bittorent_hash)-1; i++) {
            sprintf(&flow->bittorent_hash[j], "%02x", flow->ndpi_flow->bittorent_hash[i]);
            j += 2, n += flow->ndpi_flow->bittorent_hash[i];
        }

        if(n == 0) flow->bittorent_hash[0] = '\0';
    }
    /* MDNS */
    else if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_MDNS) {
        snprintf(flow->info, sizeof(flow->info), "%s", flow->ndpi_flow->protos.mdns.answer);
    }
    /* UBNTAC2 */
    else if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UBNTAC2) {
        snprintf(flow->info, sizeof(flow->info), "%s", flow->ndpi_flow->protos.ubntac2.version);
    }
    if(flow->detected_protocol.app_protocol != NDPI_PROTOCOL_DNS) {
        /* SSH */
        if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_SSH) {
            snprintf(flow->ssh_ssl.client_info, sizeof(flow->ssh_ssl.client_info), "%s",
                    flow->ndpi_flow->protos.ssh.client_signature);
            snprintf(flow->ssh_ssl.server_info, sizeof(flow->ssh_ssl.server_info), "%s",
                    flow->ndpi_flow->protos.ssh.server_signature);
        }
        /* SSL */
        else if((flow->detected_protocol.app_protocol == NDPI_PROTOCOL_SSL)
                || (flow->detected_protocol.master_protocol == NDPI_PROTOCOL_SSL)) {
            snprintf(flow->ssh_ssl.client_info, sizeof(flow->ssh_ssl.client_info), "%s",
                    flow->ndpi_flow->protos.ssl.client_certificate);
            snprintf(flow->ssh_ssl.server_info, sizeof(flow->ssh_ssl.server_info), "%s",
                    flow->ndpi_flow->protos.ssl.server_certificate);
        }
    }

    // TODO: Add HTTP related features

}
/* ***************************************************** */
static struct ndpi_flow_info *packet_processing( const u_int64_t time,
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
        updateFlowFeatures(flow,time,vlan_id,iph,iph6,ip_offset,ipsize,rawsize,src_to_dst_direction);
    } else { // flow is NULL
      return(NULL);
    }

    // Interou 500 pacotes, salva no HBASE
    if( flow->packets == HOGZILLA_MAX_NDPI_PKT_PER_FLOW)
    { HogzillaSaveFlow(flow); /* save into  HBase */ }

    // After FIN , save into HBase and remove from tree
    if(iph!=NULL && iph->protocol == IPPROTO_TCP && tcph!=NULL){
        if(tcph->fin == 1) flow->fin_stage++;

        if(flow->fin_stage==2 && tcph->fin == 0 && tcph->ack == 1){ /* Connection finished! */
            process_ndpi_collected_info(flow);
            HogzillaSaveFlow(flow);
            return flow;
        }
    }

    if(flow->detection_completed) {
        if(flow->check_extra_packets && ndpi_flow != NULL && ndpi_flow->check_extra_packets) {
            if(ndpi_flow->num_extra_packets_checked == 0 && ndpi_flow->max_extra_packets_to_check == 0) {
                /* Protocols can set this, but we set it here in case they didn't */
                ndpi_flow->max_extra_packets_to_check = MAX_EXTRA_PACKETS_TO_CHECK;
            }
            if(ndpi_flow->num_extra_packets_checked < ndpi_flow->max_extra_packets_to_check) {
                ndpi_process_extra_packet(ndpi_info.ndpi_struct, ndpi_flow,
                        iph ? (uint8_t *)iph : (uint8_t *)iph6,
                                ipsize, time, src, dst);
                if (ndpi_flow->check_extra_packets == 0) {
                    flow->check_extra_packets = 0;
                    process_ndpi_collected_info(flow);
                }
            }
        }

    }else{

        flow->detected_protocol = ndpi_detection_process_packet(ndpi_info.ndpi_struct, ndpi_flow,
                iph ? (uint8_t *)iph : (uint8_t *)iph6,
                        ipsize, time, src, dst);

        if((flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN)
                || ((proto == IPPROTO_UDP) && ((flow->src2dst_packets + flow->dst2src_packets) > 8))
                || ((proto == IPPROTO_TCP) && ((flow->src2dst_packets + flow->dst2src_packets) > 10))) {
            /* New protocol detected or give up */
            flow->detection_completed = 1;
            /* Check if we should keep checking extra packets */
            if (ndpi_flow->check_extra_packets)
                flow->check_extra_packets = 1;

            if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN)
                flow->detected_protocol = ndpi_detection_giveup(ndpi_info.ndpi_struct,flow->ndpi_flow);

            process_ndpi_collected_info(flow);
        }
    }

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
    hbase = (HogzillaHBase*) SnortAlloc(sizeof(HogzillaHBase));

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


void Hogzilla_mutations(struct ndpi_flow_info *flow, GPtrArray * mutations)
{

    char text[40][50];

    Mutation *mutation;

    // lower_ip
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:src_ip", 11);
    g_byte_array_append (mutation->value ,(guint*) &flow->src_ip,  sizeof(u_int32_t));
    g_ptr_array_add (mutations, mutation);

    // upper_ip
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:dst_ip", 11);
    g_byte_array_append (mutation->value ,(guint*) &flow->dst_ip,  sizeof(u_int32_t));
    g_ptr_array_add (mutations, mutation);

    // lower_name
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:src_name", 13);
    g_byte_array_append (mutation->value ,(guint**) flow->src_name,  strlen(flow->src_name));
    g_ptr_array_add (mutations, mutation);

    // upper_name
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:dst_name", 13);
    g_byte_array_append (mutation->value ,(guint**) flow->dst_name,  strlen(flow->dst_name));
    g_ptr_array_add (mutations, mutation);

    // lower_port
    sprintf(text[0], "%d", ntohs(flow->src_port)) ;
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:src_port", 13);
    g_byte_array_append (mutation->value ,(guint**) text[0],  strlen(text[0]));
    g_ptr_array_add (mutations, mutation);

    // upper_port
    sprintf(text[1], "%d", ntohs(flow->dst_port)) ;
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:dst_port", 13);
    g_byte_array_append (mutation->value ,(guint**) text[1],  strlen(text[1]));
    g_ptr_array_add (mutations, mutation);

    // protocol
    char * proto = ipProto2Name(flow->protocol);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:protocol", 13);
    g_byte_array_append (mutation->value ,(guint*) proto,  strlen(proto));
    g_ptr_array_add (mutations, mutation);

    // vlan_id
    sprintf(text[2], "%d", flow->vlan_id);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:vlan_id", 12);
    g_byte_array_append (mutation->value ,(guint**) text[2], strlen(text[2]));
    g_ptr_array_add (mutations, mutation);

    // last_seen
    sprintf(text[3], "%ld", flow->last_seen);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:last_seen", 14);
    g_byte_array_append (mutation->value ,(guint**) text[3], strlen(text[3]));
    g_ptr_array_add (mutations, mutation);

    // bytes
    sprintf(text[4], "%ld", flow->bytes);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:bytes", 10);
    g_byte_array_append (mutation->value ,(guint**) text[4], strlen(text[4]));
    g_ptr_array_add (mutations, mutation);

    // packets
    sprintf(text[5], "%d", flow->packets);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:packets", 12);
    g_byte_array_append (mutation->value ,(guint**) text[5], strlen(text[5]));
    g_ptr_array_add (mutations, mutation);

    // flow_duration
    sprintf(text[6], "%ld", flow->flow_duration);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:flow_duration", 18);
    g_byte_array_append (mutation->value ,(guint**) text[6], strlen(text[6]));
    g_ptr_array_add (mutations, mutation);

    // first_seen
    sprintf(text[7], "%ld", flow->first_seen);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:first_seen", 15);
    g_byte_array_append (mutation->value ,(guint**) text[7], strlen(text[7]));
    g_ptr_array_add (mutations, mutation);

    // max_packet_size
    sprintf(text[8], "%d", flow->max_packet_size);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:max_packet_size", 20);
    g_byte_array_append (mutation->value ,(guint**) text[8], strlen(text[8]));
    g_ptr_array_add (mutations, mutation);

    // min_packet_size
    sprintf(text[9], "%d", flow->min_packet_size);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:min_packet_size", 20);
    g_byte_array_append (mutation->value ,(guint**) text[9], strlen(text[9]));
    g_ptr_array_add (mutations, mutation);

    // avg_packet_size
    sprintf(text[10], "%d", flow->avg_packet_size);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:avg_packet_size", 20);
    g_byte_array_append (mutation->value ,(guint**) text[10], strlen(text[10]));
    g_ptr_array_add (mutations, mutation);

    // payload_bytes
    sprintf(text[11], "%ld", flow->payload_bytes);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:payload_bytes", 18);
    g_byte_array_append (mutation->value ,(guint**) text[11], strlen(text[11]));
    g_ptr_array_add (mutations, mutation);

    // payload_first_size
    sprintf(text[12], "%d", flow->payload_first_size);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:payload_first_size", 23);
    g_byte_array_append (mutation->value ,(guint**) text[12], strlen(text[12]));
    g_ptr_array_add (mutations, mutation);

    // payload_avg_size
    sprintf(text[13], "%d", flow->payload_avg_size);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:payload_avg_size", 21);
    g_byte_array_append (mutation->value ,(guint**) text[13], strlen(text[13]));
    g_ptr_array_add (mutations, mutation);

    // payload_min_size
    sprintf(text[14], "%d", flow->payload_min_size);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:payload_min_size", 21);
    g_byte_array_append (mutation->value ,(guint**) text[14], strlen(text[14]));
    g_ptr_array_add (mutations, mutation);

    // payload_max_size
    sprintf(text[15], "%d", flow->payload_max_size);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:payload_max_size", 21);
    g_byte_array_append (mutation->value ,(guint**) text[15], strlen(text[15]));
    g_ptr_array_add (mutations, mutation);

    // packets_without_payload
    sprintf(text[16], "%d", flow->packets_without_payload);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:packets_without_payload", 28);
    g_byte_array_append (mutation->value ,(guint**) text[16], strlen(text[16]));
    g_ptr_array_add (mutations, mutation);

    // detection_completed
    sprintf(text[17], "%d", flow->detection_completed);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:detection_completed", 24);
    g_byte_array_append (mutation->value ,(guint**) text[17], strlen(text[17]));
    g_ptr_array_add (mutations, mutation);

    // detected_protocol
    if(flow->detected_protocol.master_protocol && flow->detected_protocol.app_protocol!=NULL && flow->detected_protocol.app_protocol!=0) {
        char buf[64];

        sprintf(text[18], "%u.%u/%s",
                flow->detected_protocol.master_protocol, flow->detected_protocol.app_protocol,
                ndpi_protocol2name(ndpi_info.ndpi_struct,flow->detected_protocol, buf, sizeof(buf)));
    } else if(flow->detected_protocol.master_protocol){
        sprintf(text[18], "%u/%s",
                flow->detected_protocol.master_protocol,
                ndpi_get_proto_name(ndpi_info.ndpi_struct, flow->detected_protocol.master_protocol));
    } else {
        sprintf(text[18], "%u/%s",
                flow->detected_protocol.app_protocol,
                ndpi_get_proto_name(ndpi_info.ndpi_struct, flow->detected_protocol.app_protocol));
    }

    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:detected_protocol", 22);
    g_byte_array_append (mutation->value ,(guint**) text[18],  strlen(text[18]));
    g_ptr_array_add (mutations, mutation);


    // host_server_name
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:host_server_name", 21);
    g_byte_array_append (mutation->value ,(guint**) flow->host_server_name,  strlen(flow->host_server_name));
    g_ptr_array_add (mutations, mutation);

    // detected_os
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:detected_os", 16);
    g_byte_array_append (mutation->value ,(guint**) flow->ndpi_flow->detected_os,  strlen(flow->ndpi_flow->detected_os));
    g_ptr_array_add (mutations, mutation);



    // Packets
    int i;
    for(i=0;i<flow->packets && i<sizeof(flow->inter_time);i++)
    {
        char itime[10];
        char psize[10];
        char itimename[25];
        char psizename[25];
        sprintf(itime, "%d", flow->inter_time[i]);
        sprintf(psize, "%d", flow->packet_size[i]);
        sprintf(itimename, "flow:inter_time-%d", i);
        sprintf(psizename, "flow:packet_size-%d", i);

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
    }

    if(flow->event!=NULL)
    {
        sprintf(text[19], "%d", ntohl(flow->event->sensor_id));
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "event:sensor_id", 15);
        g_byte_array_append (mutation->value ,(guint**) text[19], strlen(text[19]));
        g_ptr_array_add (mutations, mutation);

        sprintf(text[20], "%u", ntohl(flow->event->event_id));
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "event:event_id", 14);
        g_byte_array_append (mutation->value ,(guint**) text[20], strlen(text[20]));
        g_ptr_array_add (mutations, mutation);

        sprintf(text[21], "%u", ntohl(flow->event->event_second));
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "event:event_second", 18);
        g_byte_array_append (mutation->value ,(guint**) text[21], strlen(text[21]));
        g_ptr_array_add (mutations, mutation);

        sprintf(text[22], "%u", ntohl(flow->event->event_microsecond));
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "event:event_microsecond", 23);
        g_byte_array_append (mutation->value ,(guint**) text[22], strlen(text[22]));
        g_ptr_array_add (mutations, mutation);

        sprintf(text[23], "%u", ntohl(flow->event->signature_id));
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "event:signature_id", 18);
        g_byte_array_append (mutation->value ,(guint**) text[23], strlen(text[23]));
        g_ptr_array_add (mutations, mutation);

        sprintf(text[24], "%u", ntohl(flow->event->generator_id));
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "event:generator_id", 18);
        g_byte_array_append (mutation->value ,(guint**) text[24], strlen(text[24]));
        g_ptr_array_add (mutations, mutation);

        sprintf(text[25], "%u", ntohl(flow->event->classification_id));
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "event:classification_id", 23);
        g_byte_array_append (mutation->value ,(guint**) text[25], strlen(text[25]));
        g_ptr_array_add (mutations, mutation);

        sprintf(text[26], "%u", ntohl(flow->event->priority_id));
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "event:priority_id", 17);
        g_byte_array_append (mutation->value ,(guint**) text[26], strlen(text[26]));
        g_ptr_array_add (mutations, mutation);


    }

    // avg_inter_time
    sprintf(text[27], "%d", flow->avg_inter_time);
    mutation = g_object_new (TYPE_MUTATION, NULL);
    mutation->column = g_byte_array_new ();
    mutation->value  = g_byte_array_new ();
    g_byte_array_append (mutation->column,(guint*) "flow:avg_inter_time", 19);
    g_byte_array_append (mutation->value ,(guint**) text[27], strlen(text[27]));
    g_ptr_array_add (mutations, mutation);

    // DNS stuff
    //    struct {
    //      u_int8_t num_queries, num_answers, reply_code;
    //      u_int16_t query_type, query_class, rsp_type;
    //    } dns;


    if(flow->protocol == IPPROTO_UDP && flow->detected_protocol.master_protocol == NDPI_PROTOCOL_DNS )
    {
        // for debuging
        //raise(SIGINT);
        // dns.num_queries
        sprintf(text[28], "%d", flow->ndpi_flow->protos.dns.num_queries);
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "flow:dns_num_queries", 20);
        g_byte_array_append (mutation->value ,(guint**) text[28], strlen(text[28]));
        g_ptr_array_add (mutations, mutation);

        // dns.num_answers
        sprintf(text[29], "%d", flow->ndpi_flow->protos.dns.num_answers);
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "flow:dns_num_answers", 20);
        g_byte_array_append (mutation->value ,(guint**) text[29], strlen(text[29]));
        g_ptr_array_add (mutations, mutation);

        // dns.reply_code
        sprintf(text[30], "%d", flow->ndpi_flow->protos.dns.reply_code);
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "flow:dns_reply_code", 19);
        g_byte_array_append (mutation->value ,(guint**) text[30], strlen(text[30]));
        g_ptr_array_add (mutations, mutation);

        //// dns.bad_packet DEPRECATED
        //sprintf(text[31], "%d", flow->ndpi_flow->protos.dns.bad_packet);
        //mutation = g_object_new (TYPE_MUTATION, NULL);
        //mutation->column = g_byte_array_new ();
        //mutation->value  = g_byte_array_new ();
        //g_byte_array_append (mutation->column,(guint*) "flow:dns_bad_packet", 19);
        //g_byte_array_append (mutation->value ,(guint**) text[31], strlen(text[31]));
        //g_ptr_array_add (mutations, mutation);

        // dns.query_type
        sprintf(text[32], "%d", flow->ndpi_flow->protos.dns.query_type);
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "flow:dns_query_type", 19);
        g_byte_array_append (mutation->value ,(guint**) text[32], strlen(text[32]));
        g_ptr_array_add (mutations, mutation);

        // dns.query_class
        sprintf(text[33], "%d", flow->ndpi_flow->protos.dns.query_class);
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "flow:dns_query_class", 20);
        g_byte_array_append (mutation->value ,(guint**) text[33], strlen(text[33]));
        g_ptr_array_add (mutations, mutation);

        // dns.rsp_type
        sprintf(text[34], "%d", flow->ndpi_flow->protos.dns.rsp_type);
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "flow:dns_rsp_type", 17);
        g_byte_array_append (mutation->value ,(guint**) text[34], strlen(text[34]));
        g_ptr_array_add (mutations, mutation);
    }

    if(flow->protocol == IPPROTO_TCP && flow->detected_protocol.master_protocol == NDPI_PROTOCOL_HTTP )
    {

        // http.method
        sprintf(text[35], "%d", flow->ndpi_flow->http.method);
        mutation = g_object_new (TYPE_MUTATION, NULL);
        mutation->column = g_byte_array_new ();
        mutation->value  = g_byte_array_new ();
        g_byte_array_append (mutation->column,(guint*) "flow:http_method", 16);
        g_byte_array_append (mutation->value ,(guint**) text[35], strlen(text[35]));
        g_ptr_array_add (mutations, mutation);

        // http.url
        if(flow->ndpi_flow->http.url != NULL)
        {
            mutation = g_object_new (TYPE_MUTATION, NULL);
            mutation->column = g_byte_array_new ();
            mutation->value  = g_byte_array_new ();
            g_byte_array_append (mutation->column,(guint*) "flow:http_url", 13);
            g_byte_array_append (mutation->value ,(guint**) flow->ndpi_flow->http.url,  strlen(flow->ndpi_flow->http.url));
            g_ptr_array_add (mutations, mutation);
        }

        // http.content_type
        if(flow->ndpi_flow->http.content_type != NULL)
        {
            mutation = g_object_new (TYPE_MUTATION, NULL);
            mutation->column = g_byte_array_new ();
            mutation->value  = g_byte_array_new ();
            g_byte_array_append (mutation->column,(guint*) "flow:http_content_type", 22);
            g_byte_array_append (mutation->value ,(guint**) flow->ndpi_flow->http.content_type,  strlen(flow->ndpi_flow->http.content_type));
            g_ptr_array_add (mutations, mutation);
        }
    }


    //Unified2EventCommon *event;
    //typedef struct _Unified2EventCommon
    //{
    //   uint32_t sensor_id;
    //   uint32_t event_id;
    //   uint32_t event_second;
    //   uint32_t event_microsecond;
    //   uint32_t signature_id;
    //   uint32_t generator_id;
    //   uint32_t signature_revision;
    //   uint32_t classification_id;
    //   uint32_t priority_id;
    //} Unified2EventCommon;
    //
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
            flow->event= (struct Unified2EventCommon*)malloc(sizeof(Unified2EventCommon));
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
