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
 * Packet logs are written (quickly) to a tcpdump formatted output
 * file
 *
 * Comments:
 *
 * First logger...
 *
 */

#define HOGZILLA_MAX_NDPI_FLOWS 50000
#define HOGZILLA_MAX_NDPI_PKT_PER_FLOW 500
#define HOGZILLA_MAX_EVENT_TABLE 100000
#define HOGZILLA_MAX_IDLE_TIME 30000
#define IDLE_SCAN_PERIOD       10000
#define GTP_U_V1_PORT        2152
 
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

// #include <sched.h>
#include <stdio.h>
// #include <netinet/in.h>
// #include <stdarg.h>
// #include <search.h>
// #include <signal.h>
#include "ndpi_api.h"
// #include <sys/socket.h>

#include <glib-object.h>

// Install Thrift with c_glib support
#include <thrift/c_glib/thrift.h>
#include <thrift/c_glib/protocol/thrift_binary_protocol.h>
#include <thrift/c_glib/transport/thrift_buffered_transport.h>
#include <thrift/c_glib/transport/thrift_socket.h>

#include "output-plugins/hogzilla/hbase_types.h"
#include "output-plugins/hogzilla/hbase.h"

#define NUM_ROOTS                 512
#define IDLE_SCAN_BUDGET         1024


typedef struct _HogzillaHBase
{
  ThriftSocket          *socket;
  ThriftTransport       *transport;
  ThriftProtocol        *protocol;
  HbaseIf               *client;
  GError                *error;
  IOError               *ioerror;
  IllegalArgument       *iargument;
} HogzillaHBase;

// TODO HZ
// struct
typedef struct _HogzillaData
{
    char                *hbase_host;
    u_int32_t           hbase_port;
    time_t              lastTime;
} HogzillaData;

//CSP
// - struct reader_thread  
// - declaração ndpi_info
// extraido de ndpiReader.c
//PSC

struct reader_hogzilla {
  struct ndpi_detection_module_struct *ndpi_struct;
  void *ndpi_flows_root[NUM_ROOTS];
  u_int64_t last_time;
  u_int64_t last_idle_scan_time;
  u_int32_t idle_scan_idx;
  u_int32_t num_idle_flows;
  u_int32_t ndpi_flow_count;
  void *eventById[HOGZILLA_MAX_EVENT_TABLE];
  struct ndpi_flow *idle_flows[IDLE_SCAN_BUDGET];
};

static struct reader_hogzilla ndpi_info;

/* list of function prototypes for this output plugin */
// TODO HZ
// atualizar essa lista no final
static void HogzillaInit(char *);
static HogzillaData *ParseHogzillaArgs(char *);
static void Hogzilla(Packet *, void *, uint32_t, void *);
static void SpoHogzillaCleanExitFunc(int, void *);
static void SpoHogzillaRestartFunc(int, void *);
static void HogzillaSingle(Packet *, void *, uint32_t, void *);
static void HogzillaStream(Packet *, void *, uint32_t, void *);
//static void HogzillaInitLogFileFinalize(int unused, void *arg);
//static void HogzillaInitLogFile(HogzillaData *, int);
//static void HogzillaRollLogFile(HogzillaData*);

/* If you need to instantiate the plugin's data structure, do it here */
HogzillaData *hogzilla_ptr;
HogzillaHBase * hbase;
static u_int8_t undetected_flows_deleted = 0;
static u_int32_t size_id_struct = 0;		//< ID tracking structure size
static u_int32_t size_flow_struct = 0;
static u_int32_t detection_tick_resolution = 1000;
static u_int16_t decode_tunnels = 0;

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
void HogzillaSetup(void)
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterOutputPlugin("hogzilla", OUTPUT_TYPE_FLAG__LOG, HogzillaInit);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Output plugin: Hogzilla is setup...\n"););

  size_id_struct = ndpi_detection_get_sizeof_ndpi_id_struct();
  size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();
  ndpi_info = (struct reader_hogzilla*)malloc(sizeof(struct reader_hogzilla));
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
static void HogzillaInit(char *args)
{
    HogzillaData *data;
    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Output: Hogzilla Initialized\n"););

    /* parse the argument list from the rules file */
    data = ParseHogzillaArgs(args);
    hogzilla_ptr = data;

    //AddFuncToPostConfigList(HogzillaInitLogFileFinalize, data);
    //DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Linking Hogzilla functions to call lists...\n"););
    
    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(Hogzilla, OUTPUT_TYPE__LOG, data);
    AddFuncToCleanExitList(SpoHogzillaCleanExitFunc, data);
    AddFuncToRestartList(SpoHogzillaRestartFunc, data);
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
static HogzillaData *ParseHogzillaArgs(char *args)
{
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
    {
        FatalError("hogzilla: unable to allocate memory!\n");
    }
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
                //TODO HZ: Colocar o nome do banco, se necessario ou gerar erro
                break;
        }
    }
    mSplitFree(&toks, num_toks);

    DEBUG_WRAP(DebugMessage(
        DEBUG_INIT, "hogzilla should save on host %s port %ld\n", data->hbase_host, data->hbase_port
    ););
    return data;
}

// static INLINE size_t SizeOf (const struct pcap_pkthdr *pkth)
// {
//     return PCAP_PKT_HDR_SZ + pkth->caplen;
// }

static void closeHBase(void)
{
  thrift_transport_close (hbase->transport, NULL);
  g_object_unref (hbase->client);
  g_object_unref (hbase->protocol);
  g_object_unref (hbase->transport);
  g_object_unref (hbase->socket);
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
static void SpoHogzillaCleanup(int signal, void *arg, const char* msg)
{
  // Fecha conexão no banco
  // limpar memoria ocupada pelo nDPI
  // Gera log
  
    /* cast the arg pointer to the proper type */
    HogzillaData *data = (HogzillaData *) arg;

    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"%s\n", msg););

    closeHBase();

    memset(data,'\0',sizeof(HogzillaData));
    free(data);
}

static void SpoHogzillaCleanExitFunc(int signal, void *arg)
{
    SpoHogzillaCleanup(signal, arg, "SpoHogzillaCleanExitFunc");
}

static void SpoHogzillaRestartFunc(int signal, void *arg)
{
    SpoHogzillaCleanup(signal, arg, "SpoHogzillaRestartFunc");
}



// CSP
// Observação: SpoHogzillaCleanExitFunc e SpoHogzillaRestartFunc fazem a mesma coisa, chamam a função SpoHogzillaCleanup
//				pode diferenciar na passagem de parametros!! Observar!!!
// PSC


// flow tracking
typedef struct ndpi_flow {
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  u_int8_t detection_completed, protocol;
  u_int16_t vlan_id;
  struct ndpi_flow_struct *ndpi_flow;
  char lower_name[32], upper_name[32];

  u_int64_t last_seen;

  u_int64_t bytes;
  u_int32_t packets;
  //PA
  u_int32_t max_packet_size;
  u_int32_t min_packet_size;
  u_int32_t avg_packet_size;

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
  //AP

  // result only, not used for flow identification
  ndpi_protocol detected_protocol;

  char host_server_name[256];

  struct {
    char client_certificate[48], server_certificate[48];
  } ssl;

  void *src_id, *dst_id;
} ndpi_flow_t;



static u_int16_t node_guess_undetected_protocol(struct ndpi_flow *flow) {
  flow->detected_protocol = ndpi_guess_undetected_protocol(ndpi_info.ndpi_struct,
							   flow->protocol,
							   ntohl(flow->lower_ip),
							   ntohs(flow->lower_port),
							   ntohl(flow->upper_ip),
							   ntohs(flow->upper_port));
  // printf("Guess state: %u\n", flow->detected_protocol);

  return(flow->detected_protocol.protocol);
}


/* ***************************************************** */
static void node_proto_guess_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow *flow = *(struct ndpi_flow **) node;

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
      if(flow->detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN) {
    node_guess_undetected_protocol(flow);
    // printFlow(thread_id, flow);
      }

  }
}
/* ***************************************************** */

void HogzillaSaveFlow(struct ndpi_flow *flow)
{
  char str[100];

  // Salvar no HBASE
  //   . Ver se tá conectado, senao conecta
     hbase = connectHBase();
     //GPtrArray *lista ;
     //lista = g_ptr_array_new ();
     GHashTable * attributes = g_hash_table_new(g_str_hash, g_str_equal);
     GPtrArray * mutations;
     mutations = g_ptr_array_new ();
     
     Hogzilla_mutations(&flow,&mutations);
     
     Text * tabela = g_byte_array_new ();
     g_byte_array_append (tabela, (guint8*) "hogzilla_flows", 14);

     Text * chave ;
     //TODO HZ: encontrar uma chave única melhor para cada flow
     sprintf(str, "%lld.%lld", flow->first_seen,flow->lower_ip) ;
     chave = g_byte_array_new ();
     g_byte_array_append (chave,(guint8*) str,  strlen(str));

     hbase_client_mutate_row (hbase->client, tabela, chave, mutations,attributes, &hbase->ioerror, &hbase->iargument, &hbase->error);
     //TODO HZ:  Trata os errors ioerror, iargument, error
}

/* ***************************************************** */
static void free_ndpi_flow(struct ndpi_flow *flow) {
  if(flow->ndpi_flow) { ndpi_free_flow(flow->ndpi_flow); flow->ndpi_flow = NULL; }
  if(flow->src_id)    { ndpi_free(flow->src_id); flow->src_id = NULL;       }
  if(flow->dst_id)    { ndpi_free(flow->dst_id); flow->dst_id = NULL;       }

}
/* ***************************************************** */

static void node_idle_scan_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow *flow = *(struct ndpi_flow **) node;
  
  
  //  Conexões idle, salva no HBASE e apaga

  if(ndpi_info.num_idle_flows == IDLE_SCAN_BUDGET) /* TODO optimise with a budget-based walk */
    return;

  if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
    if(flow->last_seen + HOGZILLA_MAX_IDLE_TIME < ndpi_info.last_time) {

      /* update stats */
      node_proto_guess_walker(node, which, depth, user_data);

      if((flow->detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN) && !undetected_flows_deleted)
        undetected_flows_deleted = 1;
      
      // TODO HZ: HogzillaSaveFlow 
	  // --- salvar no HBASE??
      HogzillaSaveFlow(flow);
      free_ndpi_flow(flow);

      /* adding to a queue (we can't delete it from the tree inline ) */
      ndpi_info.idle_flows[ndpi_info.num_idle_flows++] = flow;
    }
  }
}
/* ***************************************************** */

static int node_cmp(const void *a, const void *b) {
  struct ndpi_flow *fa = (struct ndpi_flow*)a;
  struct ndpi_flow *fb = (struct ndpi_flow*)b;

  if(fa->vlan_id   < fb->vlan_id  )   return(-1); else { if(fa->vlan_id   > fb->vlan_id  )   return(1); }
  if(fa->lower_ip   < fb->lower_ip  ) return(-1); else { if(fa->lower_ip   > fb->lower_ip  ) return(1); }
  if(fa->lower_port < fb->lower_port) return(-1); else { if(fa->lower_port > fb->lower_port) return(1); }
  if(fa->upper_ip   < fb->upper_ip  ) return(-1); else { if(fa->upper_ip   > fb->upper_ip  ) return(1); }
  if(fa->upper_port < fb->upper_port) return(-1); else { if(fa->upper_port > fb->upper_port) return(1); }
  if(fa->protocol   < fb->protocol  ) return(-1); else { if(fa->protocol   > fb->protocol  ) return(1); }

  return(0);
}

/* ***************************************************** */

static struct ndpi_flow *get_ndpi_flow( const u_int8_t version,
                       u_int16_t vlan_id,
                       const struct ndpi_iphdr *iph,
                       u_int16_t ip_offset,
                       u_int16_t ipsize,
                       u_int16_t l4_packet_len,
                       struct ndpi_id_struct **src,
                       struct ndpi_id_struct **dst,
                       u_int8_t *proto,
                       const struct ndpi_ip6_hdr *iph6) {
  u_int32_t idx, l4_offset;
  struct ndpi_tcphdr *tcph = NULL;
  struct ndpi_udphdr *udph = NULL;
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  struct ndpi_flow flow;
  void *ret;
  u_int8_t *l3;

  /*
    Note: to keep things simple (ndpiReader is just a demo app)
    we handle IPv6 a-la-IPv4.
  */
  if(version == 4) {
    if(ipsize < 20)
      return NULL;

    if((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len)
       || (iph->frag_off & htons(0x1FFF)) != 0)
      return NULL;

    l4_offset = iph->ihl * 4;
    l3 = (u_int8_t*)iph;
  } else {
    l4_offset = sizeof(struct ndpi_ip6_hdr);
    l3 = (u_int8_t*)iph6;
  }

  if(iph->saddr < iph->daddr) {
    lower_ip = iph->saddr;
    upper_ip = iph->daddr;
  } else {
    lower_ip = iph->daddr;
    upper_ip = iph->saddr;
  }

  *proto = iph->protocol;

  if(iph->protocol == 6 && l4_packet_len >= 20) {
    // tcp
    tcph = (struct ndpi_tcphdr *) ((u_int8_t *) l3 + l4_offset);
    if(iph->saddr < iph->daddr) {
      lower_port = tcph->source;
      upper_port = tcph->dest;
    } else {
      lower_port = tcph->dest;
      upper_port = tcph->source;

      if(iph->saddr == iph->daddr) {
    if(lower_port > upper_port) {
      u_int16_t p = lower_port;

      lower_port = upper_port;
      upper_port = p;
    }
      }
    }
  } else if(iph->protocol == 17 && l4_packet_len >= 8) {
    // udp
    udph = (struct ndpi_udphdr *) ((u_int8_t *) l3 + l4_offset);
    if(iph->saddr < iph->daddr) {
      lower_port = udph->source;
      upper_port = udph->dest;
    } else {
      lower_port = udph->dest;
      upper_port = udph->source;
    }
  } else {
    // non tcp/udp protocols
    lower_port = 0;
    upper_port = 0;
  }

  flow.protocol = iph->protocol, flow.vlan_id = vlan_id;
  flow.lower_ip = lower_ip, flow.upper_ip = upper_ip;
  flow.lower_port = lower_port, flow.upper_port = upper_port;

//  if(0)
//    printf("[NDPI] [%u][%u:%u <-> %u:%u]\n",
//     iph->protocol, lower_ip, ntohs(lower_port), upper_ip, ntohs(upper_port));

  idx = (vlan_id + lower_ip + upper_ip + iph->protocol + lower_port + upper_port) % NUM_ROOTS;
  ret = ndpi_tfind(&flow, &ndpi_info.ndpi_flows_root[idx], node_cmp);

  if(ret == NULL) {
    if(ndpi_info.ndpi_flow_count == HOGZILLA_MAX_NDPI_FLOWS) {
      printf("ERROR: maximum flow count (%u) has been exceeded\n", HOGZILLA_MAX_NDPI_FLOWS);
      exit(-1);
    } else {
      struct ndpi_flow *newflow = (struct ndpi_flow*)malloc(sizeof(struct ndpi_flow));

      if(newflow == NULL) {
    printf("[NDPI] %s(1): not enough memory\n", __FUNCTION__);
    return(NULL);
      }

      memset(newflow, 0, sizeof(struct ndpi_flow));
      newflow->protocol = iph->protocol, newflow->vlan_id = vlan_id;
      newflow->lower_ip = lower_ip, newflow->upper_ip = upper_ip;
      newflow->lower_port = lower_port, newflow->upper_port = upper_port;
      //PA NEWFLOW
      newflow->min_packet_size=999999;
      newflow->payload_min_size=999999;
      //AP

      if(version == 4) {
    inet_ntop(AF_INET, &lower_ip, newflow->lower_name, sizeof(newflow->lower_name));
    inet_ntop(AF_INET, &upper_ip, newflow->upper_name, sizeof(newflow->upper_name));
      } else {
    inet_ntop(AF_INET6, &iph6->ip6_src, newflow->lower_name, sizeof(newflow->lower_name));
    inet_ntop(AF_INET6, &iph6->ip6_dst, newflow->upper_name, sizeof(newflow->upper_name));
      }

      if((newflow->ndpi_flow = malloc(size_flow_struct)) == NULL) {
    printf("[NDPI] %s(2): not enough memory\n", __FUNCTION__);
    free(newflow);
    return(NULL);
      } else
    memset(newflow->ndpi_flow, 0, size_flow_struct);
      if((newflow->src_id = malloc(size_id_struct)) == NULL) {
    printf("[NDPI] %s(3): not enough memory\n", __FUNCTION__);
    free(newflow);
    return(NULL);
      } else
    memset(newflow->src_id, 0, size_id_struct);

      if((newflow->dst_id = malloc(size_id_struct)) == NULL) {
    printf("[NDPI] %s(4): not enough memory\n", __FUNCTION__);
    free(newflow);
    return(NULL);
      } else
    memset(newflow->dst_id, 0, size_id_struct);

      ndpi_tsearch(newflow, &ndpi_info.ndpi_flows_root[idx], node_cmp); /* Add */
      ndpi_info.ndpi_flow_count++;

      *src = newflow->src_id, *dst = newflow->dst_id;

      // printFlow(thread_id, newflow);

      return newflow ;
    }
  } else {
    struct ndpi_flow *flow = *(struct ndpi_flow**)ret;

    if(flow->lower_ip == lower_ip && flow->upper_ip == upper_ip
       && flow->lower_port == lower_port && flow->upper_port == upper_port)
      *src = flow->src_id, *dst = flow->dst_id;
    else
      *src = flow->dst_id, *dst = flow->src_id;

    return flow;
  }
}

/* ***************************************************** */
static struct ndpi_flow *get_ndpi_flow6(u_int16_t vlan_id,
                    const struct ndpi_ip6_hdr *iph6,
                    u_int16_t ip_offset,
                    struct ndpi_id_struct **src,
                    struct ndpi_id_struct **dst,
                    u_int8_t *proto) {
  struct ndpi_iphdr iph;

  memset(&iph, 0, sizeof(iph));
  iph.version = 4;
  iph.saddr = iph6->ip6_src.__u6_addr.__u6_addr32[2] + iph6->ip6_src.__u6_addr.__u6_addr32[3];
  iph.daddr = iph6->ip6_dst.__u6_addr.__u6_addr32[2] + iph6->ip6_dst.__u6_addr.__u6_addr32[3];
  iph.protocol = iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt;

  if(iph.protocol == 0x3C /* IPv6 destination option */) {
    u_int8_t *options = (u_int8_t*)iph6 + sizeof(const struct ndpi_ip6_hdr);

    iph.protocol = options[0];
  }

  return(get_ndpi_flow(6, vlan_id, &iph, ip_offset,
               sizeof(struct ndpi_ip6_hdr),
               ntohs(iph6->ip6_ctlun.ip6_un1.ip6_un1_plen),
               src, dst, proto, iph6));
}

/* ***************************************************** */
static void updateFlowFeatures(struct ndpi_flow *flow,
                      const u_int64_t time,
                      u_int16_t vlan_id,
                      const struct ndpi_iphdr *iph,
                      struct ndpi_ip6_hdr *iph6,
                      u_int16_t ip_offset,
                      u_int16_t ipsize,
                      u_int16_t rawsize) {

    if(flow->packets<HOGZILLA_MAX_NDPI_PKT_PER_FLOW)
    {
        flow->inter_time[flow->packets] = time - flow->last_seen;
        flow->packet_size[flow->packets]=rawsize;
        flow->avg_packet_size  = (flow->avg_packet_size*flow->packets  + rawsize)/(flow->packets+1);
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

    if(ipsize==0)
        flow->packets_without_payload++;

    flow->flow_duration = time - flow->first_seen;
}
/* ***************************************************** */

static struct ndpi_flow * packet_processing_by_pcap(const struct pcap_pkthdr *header, const u_char *packet) {
  const struct ndpi_ethhdr *ethernet;
  struct ndpi_iphdr *iph;
  struct ndpi_ip6_hdr *iph6;
  u_int64_t time;
  u_int16_t type, ip_offset, ip_len;
  u_int16_t frag_off = 0, vlan_id = 0;
  u_int8_t proto = 0, vlan_packet = 0;

  // printf("[ndpiReader] pcap_packet_callback : [%u.%u.%u.%u.%u -> %u.%u.%u.%u.%u]\n", ethernet->h_dest[1],ethernet->h_dest[2],ethernet->h_dest[3],ethernet->h_dest[4],ethernet->h_dest[5],ethernet->h_source[1],ethernet->h_source[2],ethernet->h_source[3],ethernet->h_source[4],ethernet->h_source[5]);


  time = ((uint64_t) header->ts.tv_sec) * detection_tick_resolution +
    header->ts.tv_usec / (1000000 / detection_tick_resolution);

  if(ndpi_info.last_time > time) { /* safety check */
    // printf("\nWARNING: timestamp bug in the pcap file (ts delta: %llu, repairing)\n", ndpi_info.last_time - time);
    time = ndpi_info.last_time;
  }
  ndpi_info.last_time = time;

  //if(ndpi_info._pcap_datalink_type == DLT_NULL) {
    if(ntohl(*((u_int32_t*)packet)) == 2)
      type = ETH_P_IP;
    else
      type = 0x86DD; /* IPv6 */

    ip_offset = 4;
  //} else if(ndpi_info._pcap_datalink_type == DLT_EN10MB) {
  //  ethernet = (struct ndpi_ethhdr *) packet;
  //  ip_offset = sizeof(struct ndpi_ethhdr);
  //  type = ntohs(ethernet->h_proto);
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
	    printf("\n\nWARNING: packet capture size is smaller than packet size, DETECTION MIGHT NOT WORK CORRECTLY\n\n");
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
         printf("\n\nWARNING: IPv4 fragments are not handled by this demo (nDPI supports them)\n");
	     ipv4_frags_warning_used = 1;
      }

      return;
    }
  } else if(iph->version == 6) {
    iph6 = (struct ndpi_ip6_hdr *)&packet[ip_offset];
    proto = iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    ip_len = sizeof(struct ndpi_ip6_hdr);

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
      printf("\n\nWARNING: only IPv4/IPv6 packets are supported in this demo (nDPI supports both IPv4 and IPv6), all other packets will be discarded\n\n");
      ipv4_warning_used = 1;
    }

    return;
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

//


/* ***************************************************** */
// ipsize = header->len - ip_offset ; rawsize = header->len
static struct ndpi_flow * packet_processing( const u_int64_t time,
				      u_int16_t vlan_id,
				      const struct ndpi_iphdr *iph,
				      struct ndpi_ip6_hdr *iph6,
				      u_int16_t ip_offset,
				      u_int16_t ipsize, u_int16_t rawsize) {
  struct ndpi_id_struct *src, *dst;
  struct ndpi_flow *flow;
  struct ndpi_flow_struct *ndpi_flow = NULL;
  u_int8_t proto;

  if(iph)
    flow = get_ndpi_flow(4, vlan_id, iph, ip_offset, ipsize,
			 ntohs(iph->tot_len) - (iph->ihl * 4),
			 &src, &dst, &proto, NULL);
  else
    flow = get_ndpi_flow6(vlan_id, iph6, ip_offset, &src, &dst, &proto);

  if(flow != NULL) {
     updateFlowFeatures(flow,time,vlan_id,iph,iph6,ip_offset,ipsize,rawsize);
     ndpi_flow = flow->ndpi_flow;
  } else {
    return NULL;
  }

  // TODO HZ
  // Interou 500 pacotes, salva no HBASE
  if( flow->packets == HOGZILLA_MAX_NDPI_PKT_PER_FLOW)
  { HogzillaSaveFlow(flow); /*salva no HBASE*/return &flow;}
  
  // TODO HZ
  // Conexão acabou? salva no HBASE e tira da árvore
   //if( packet->tcp->fin == 1 || packet->tcp->rst == 1 )
   // if( packet->tcp->fin == 1 || packet->tcp->rst == 1 )
   // {
   //     HogzillaSaveFlow(flow); 
   // }

  if(flow->detection_completed) return &flow;

  flow->detected_protocol = ndpi_detection_process_packet(ndpi_info.ndpi_struct, ndpi_flow,
							  iph ? (uint8_t *)iph : (uint8_t *)iph6,
							  ipsize, time, src, dst);

  if((flow->detected_protocol.protocol != NDPI_PROTOCOL_UNKNOWN)
     || ((proto == IPPROTO_UDP) && (flow->packets > 8))
     || ((proto == IPPROTO_TCP) && (flow->packets > 10))) {
    flow->detection_completed = 1;

    if((flow->detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN) && (ndpi_flow->num_stun_udp_pkts > 0))
      ndpi_set_detected_protocol(ndpi_info.ndpi_struct, ndpi_flow, NDPI_PROTOCOL_STUN, NDPI_PROTOCOL_UNKNOWN);

    snprintf(flow->host_server_name, sizeof(flow->host_server_name), "%s", flow->ndpi_flow->host_server_name);

    if((proto == IPPROTO_TCP) && (flow->detected_protocol.protocol != NDPI_PROTOCOL_DNS)) {
      snprintf(flow->ssl.client_certificate, sizeof(flow->ssl.client_certificate), "%s", flow->ndpi_flow->protos.ssl.client_certificate);
      snprintf(flow->ssl.server_certificate, sizeof(flow->ssl.server_certificate), "%s", flow->ndpi_flow->protos.ssl.server_certificate);
    }

#if 0
    if(verbose > 1) {
      if(ndpi_is_proto(flow->detected_protocol, NDPI_PROTOCOL_HTTP)) {
	char *method;

	printf("[URL] %s\n", ndpi_get_http_url(ndpi_info.ndpi_struct, ndpi_flow));
	printf("[Content-Type] %s\n", ndpi_get_http_content_type(ndpi_info.ndpi_struct, ndpi_flow));

	switch(ndpi_get_http_method(ndpi_info.ndpi_struct, ndpi_flow)) {
	case HTTP_METHOD_OPTIONS: method = "HTTP_METHOD_OPTIONS"; break;
	case HTTP_METHOD_GET:     method = "HTTP_METHOD_GET"; break;
	case HTTP_METHOD_HEAD:    method = "HTTP_METHOD_HEAD"; break;
	case HTTP_METHOD_POST:    method = "HTTP_METHOD_POST"; break;
	case HTTP_METHOD_PUT:     method = "HTTP_METHOD_PUT"; break;
	case HTTP_METHOD_DELETE:  method = "HTTP_METHOD_DELETE"; break;
	case HTTP_METHOD_TRACE:   method = "HTTP_METHOD_TRACE"; break;
	case HTTP_METHOD_CONNECT: method = "HTTP_METHOD_CONNECT"; break;
	default:                  method = "HTTP_METHOD_UNKNOWN"; break;
	}

	printf("[Method] %s\n", method);
      }
    }
#endif

    free_ndpi_flow(flow);

   //  if(verbose > 1) {
   //    if(enable_protocol_guess) {
   //  if(flow->detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN) {
   //    flow->detected_protocol.protocol = node_guess_undetected_protocol(thread_id, flow),
   //      flow->detected_protocol.master_protocol = NDPI_PROTOCOL_UNKNOWN;
   //  }
   //    }

   //    printFlow(thread_id, flow);
   //  }
  }

#if 0
  if(ndpi_flow->l4.tcp.host_server_name[0] != '\0')
    printf("%s\n", ndpi_flow->l4.tcp.host_server_name);
#endif

  // TODO HZ:
  if(ndpi_info.last_idle_scan_time + IDLE_SCAN_PERIOD < ndpi_info.last_time) {
    /* scan for idle flows */
    ndpi_twalk(ndpi_info.ndpi_flows_root[ndpi_info.idle_scan_idx], node_idle_scan_walker,NULL);

    /* remove idle flows (unfortunately we cannot do this inline) */
    while (ndpi_info.num_idle_flows > 0)
  ndpi_tdelete(ndpi_info.idle_flows[--ndpi_info.num_idle_flows],
  	     &ndpi_info.ndpi_flows_root[ndpi_info.idle_scan_idx], node_cmp);

    if(++ndpi_info.idle_scan_idx == NUM_ROOTS) ndpi_info.idle_scan_idx = 0;
    ndpi_info.last_idle_scan_time = ndpi_info.last_time;
  }

  return &flow;
}


HogzillaHBase *connectHBase()
{

  // Verifica se está aberta ou não
  if(false){}

  HogzillaHBase *hbase;
  hbase = (HogzillaHBase *) SnortAlloc(sizeof(HogzillaHBase));

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
  return &hbase;
}


void Hogzilla_mutations(struct ndpi_flow *flow, GPtrArray * mutations)
{

Mutation *mutation;

// lower_ip
mutation = g_object_new (TYPE_MUTATION, NULL);
mutation->column = g_byte_array_new ();
mutation->value  = g_byte_array_new ();
g_byte_array_append (mutation->column,(guint8*) "flow:lower_ip", 32);
g_byte_array_append (mutation->value ,(guint8*) flow->lower_ip,  sizeof(u_int32_t));
g_ptr_array_add (mutations, mutation);

// upper_ip
mutation = g_object_new (TYPE_MUTATION, NULL);
mutation->column = g_byte_array_new ();
mutation->value  = g_byte_array_new ();
g_byte_array_append (mutation->column,(guint8*) "flow:upper_ip", 32);
g_byte_array_append (mutation->value ,(guint8*) flow->upper_ip,  sizeof(u_int32_t));
g_ptr_array_add (mutations, mutation);

// lower_port
mutation = g_object_new (TYPE_MUTATION, NULL);
mutation->column = g_byte_array_new ();
mutation->value  = g_byte_array_new ();
g_byte_array_append (mutation->column,(guint8*) "flow:lower_port", 36);
g_byte_array_append (mutation->value ,(guint8*) flow->lower_port,  sizeof(u_int16_t));
g_ptr_array_add (mutations, mutation);

// upper_port
mutation = g_object_new (TYPE_MUTATION, NULL);
mutation->column = g_byte_array_new ();
mutation->value  = g_byte_array_new ();
g_byte_array_append (mutation->column,(guint8*) "flow:upper_port", 36);
g_byte_array_append (mutation->value ,(guint8*) flow->upper_port,  sizeof(u_int16_t));
g_ptr_array_add (mutations, mutation);

// protocol
mutation = g_object_new (TYPE_MUTATION, NULL);
mutation->column = g_byte_array_new ();
mutation->value  = g_byte_array_new ();
g_byte_array_append (mutation->column,(guint8*) "flow:protocol", 31);
g_byte_array_append (mutation->value ,(guint8*) flow->protocol,  sizeof(u_int8_t));
g_ptr_array_add (mutations, mutation);

// vlan_id
mutation = g_object_new (TYPE_MUTATION, NULL);
mutation->column = g_byte_array_new ();
mutation->value  = g_byte_array_new ();
g_byte_array_append (mutation->column,(guint8*) "flow:vlan_id", 30);
g_byte_array_append (mutation->value ,(guint8*) flow->vlan_id,  sizeof(u_int16_t));
g_ptr_array_add (mutations, mutation);

// last_seen
mutation = g_object_new (TYPE_MUTATION, NULL);
mutation->column = g_byte_array_new ();
mutation->value  = g_byte_array_new ();
g_byte_array_append (mutation->column,(guint8*) "flow:last_seen", 34);
g_byte_array_append (mutation->value ,(guint8*) flow->last_seen,  sizeof(u_int64_t));
g_ptr_array_add (mutations, mutation);

// bytes
mutation = g_object_new (TYPE_MUTATION, NULL);
mutation->column = g_byte_array_new ();
mutation->value  = g_byte_array_new ();
g_byte_array_append (mutation->column,(guint8*) "flow:bytes", 26);
g_byte_array_append (mutation->value ,(guint8*) flow->bytes,  sizeof(u_int64_t));
g_ptr_array_add (mutations, mutation);

// packets
mutation = g_object_new (TYPE_MUTATION, NULL);
mutation->column = g_byte_array_new ();
mutation->value  = g_byte_array_new ();
g_byte_array_append (mutation->column,(guint8*) "flow:packets", 30);
g_byte_array_append (mutation->value ,(guint8*) flow->packets,  sizeof(u_int32_t));
g_ptr_array_add (mutations, mutation);

// flow_duration
mutation = g_object_new (TYPE_MUTATION, NULL);
mutation->column = g_byte_array_new ();
mutation->value  = g_byte_array_new ();
g_byte_array_append (mutation->column,(guint8*) "flow:flow_duration", 42);
g_byte_array_append (mutation->value ,(guint8*) flow->flow_duration,  sizeof(u_int64_t));
g_ptr_array_add (mutations, mutation);

// first_seen
mutation = g_object_new (TYPE_MUTATION, NULL);
mutation->column = g_byte_array_new ();
mutation->value  = g_byte_array_new ();
g_byte_array_append (mutation->column,(guint8*) "flow:first_seen", 36);
g_byte_array_append (mutation->value ,(guint8*) flow->first_seen,  sizeof(u_int64_t));
g_ptr_array_add (mutations, mutation);

// max_packet_size
mutation = g_object_new (TYPE_MUTATION, NULL);
mutation->column = g_byte_array_new ();
mutation->value  = g_byte_array_new ();
g_byte_array_append (mutation->column,(guint8*) "flow:max_packet_size", 46);
g_byte_array_append (mutation->value ,(guint8*) flow->max_packet_size,  sizeof(u_int32_t));
g_ptr_array_add (mutations, mutation);

// min_packet_size
mutation = g_object_new (TYPE_MUTATION, NULL);
mutation->column = g_byte_array_new ();
mutation->value  = g_byte_array_new ();
g_byte_array_append (mutation->column,(guint8*) "flow:min_packet_size", 46);
g_byte_array_append (mutation->value ,(guint8*) flow->min_packet_size,  sizeof(u_int32_t));
g_ptr_array_add (mutations, mutation);

// avg_packet_size
mutation = g_object_new (TYPE_MUTATION, NULL);
mutation->column = g_byte_array_new ();
mutation->value  = g_byte_array_new ();
g_byte_array_append (mutation->column,(guint8*) "flow:avg_packet_size", 46);
g_byte_array_append (mutation->value ,(guint8*) flow->avg_packet_size,  sizeof(u_int32_t));
g_ptr_array_add (mutations, mutation);

// payload_bytes
mutation = g_object_new (TYPE_MUTATION, NULL);
mutation->column = g_byte_array_new ();
mutation->value  = g_byte_array_new ();
g_byte_array_append (mutation->column,(guint8*) "flow:payload_bytes", 42);
g_byte_array_append (mutation->value ,(guint8*) flow->payload_bytes,  sizeof(u_int64_t));
g_ptr_array_add (mutations, mutation);

// payload_first_size
mutation = g_object_new (TYPE_MUTATION, NULL);
mutation->column = g_byte_array_new ();
mutation->value  = g_byte_array_new ();
g_byte_array_append (mutation->column,(guint8*) "flow:payload_first_size", 52);
g_byte_array_append (mutation->value ,(guint8*) flow->payload_first_size,  sizeof(u_int32_t));
g_ptr_array_add (mutations, mutation);

// payload_avg_size
mutation = g_object_new (TYPE_MUTATION, NULL);
mutation->column = g_byte_array_new ();
mutation->value  = g_byte_array_new ();
g_byte_array_append (mutation->column,(guint8*) "flow:payload_avg_size", 48);
g_byte_array_append (mutation->value ,(guint8*) flow->payload_avg_size,  sizeof(u_int32_t));
g_ptr_array_add (mutations, mutation);

// payload_min_size
mutation = g_object_new (TYPE_MUTATION, NULL);
mutation->column = g_byte_array_new ();
mutation->value  = g_byte_array_new ();
g_byte_array_append (mutation->column,(guint8*) "flow:payload_min_size", 48);
g_byte_array_append (mutation->value ,(guint8*) flow->payload_min_size,  sizeof(u_int32_t));
g_ptr_array_add (mutations, mutation);

// payload_max_size
mutation = g_object_new (TYPE_MUTATION, NULL);
mutation->column = g_byte_array_new ();
mutation->value  = g_byte_array_new ();
g_byte_array_append (mutation->column,(guint8*) "flow:payload_max_size", 48);
g_byte_array_append (mutation->value ,(guint8*) flow->payload_max_size,  sizeof(u_int32_t));
g_ptr_array_add (mutations, mutation);

// packets_without_payload
mutation = g_object_new (TYPE_MUTATION, NULL);
mutation->column = g_byte_array_new ();
mutation->value  = g_byte_array_new ();
g_byte_array_append (mutation->column,(guint8*) "flow:packets_without_payload", 62);
g_byte_array_append (mutation->value ,(guint8*) flow->packets_without_payload,  sizeof(u_int32_t));
g_ptr_array_add (mutations, mutation);

// detection_completed
mutation = g_object_new (TYPE_MUTATION, NULL);
mutation->column = g_byte_array_new ();
mutation->value  = g_byte_array_new ();
g_byte_array_append (mutation->column,(guint8*) "flow:detection_completed", 53);
g_byte_array_append (mutation->value ,(guint8*) flow->detection_completed,  sizeof(u_int8_t));
g_ptr_array_add (mutations, mutation);

// detected_protocol
mutation = g_object_new (TYPE_MUTATION, NULL);
mutation->column = g_byte_array_new ();
mutation->value  = g_byte_array_new ();
g_byte_array_append (mutation->column,(guint8*) "flow:detected_protocol", 50);
g_byte_array_append (mutation->value ,(guint8*) flow->detected_protocol,  sizeof(u_int32_t));
g_ptr_array_add (mutations, mutation);

// host_server_name
mutation = g_object_new (TYPE_MUTATION, NULL);
mutation->column = g_byte_array_new ();
mutation->value  = g_byte_array_new ();
g_byte_array_append (mutation->column,(guint8*) "flow:host_server_name", 43);
g_byte_array_append (mutation->value ,(guint8*) flow->host_server_name,  sizeof(char));
g_ptr_array_add (mutations, mutation);

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

   uint32_t event_id;
   struct ndpi_flow *flow; 

// Processar na nDPI
//    . lá na nDPI, quando ocorrer uma das abaixo, o flow deve ser salvo no HBASE
//       i  ) Conexão terminou
//       ii ) Atingiu 500 pacotes no fluxo
//       iii) A conexão ficou IDLE por mais de HOGZILLA_MAX_IDLE_TIME

   if(event!=NULL)
   {
       event_id = ntohl(((Unified2EventCommon *)event)->event_id);
       ndpi_info->eventById[event_id]= &event;
   }else
   {
       // TODO HZ:
       // A partir de *p, criar chamada para a função abaixo
       flow=packet_processing_by_pcap( p->pkth, p->pkt);
       flow->event=ndpi_info->eventById[p->event_id];
   }

   //OU
       flow=packet_processing_by_pcap( p->pkth, p->pkt);
       if(event!=NULL)
          flow->event=event;

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
}


//
