#!/bin/bash

ii=0;

for i in `cat << EOF
flow:first_seen|u_int64_t|first_seen
flow:bittorent_hash|char|bittorent_hash
flow:info|char|info
flow:host_server_name|char|host_server_name
flow:ssh_ssl_client_info|char|ssh_ssl.client_info
flow:ssh_ssl_server_info|char|ssh_ssl.server_info
flow:src_ip|u_int32_t|src_ip
flow:dst_ip|u_int32_t|dst_ip
flow:src_port|u_int16_t|src_port
flow:dst_port|u_int16_t|dst_port
flow:protocol|u_int8_t|protocol
flow:bidirectional|u_int8_t|bidirectional
flow:src_name|char|src_name
flow:dst_name|char|dst_name
flow:bytes|u_int64_t|bytes
flow:packets|u_int32_t|packets
flow:payload_bytes|u_int64_t|payload_bytes
flow:packets_without_payload|u_int32_t|packets_without_payload
flow:payload_bytes_first|u_int32_t|payload_bytes_first
flow:flow_duration|u_int64_t|flow_duration
flow:src2dst_pay_bytes|u_int64_t|src2dst_pay_bytes
flow:dst2src_pay_bytes|u_int64_t|dst2src_pay_bytes
flow:src2dst_header_bytes|u_int64_t|src2dst_header_bytes
flow:dst2src_header_bytes|u_int64_t|dst2src_header_bytes
flow:src2dst_packets|u_int32_t|src2dst_packets
flow:dst2src_packets|u_int32_t|dst2src_packets
flow:src2dst_inter_time_avg|u_int64_t|src2dst_inter_time_avg
flow:src2dst_inter_time_min|u_int64_t|src2dst_inter_time_min
flow:src2dst_inter_time_max|u_int64_t|src2dst_inter_time_max
flow:src2dst_inter_time_std|u_int64_t|src2dst_inter_time_std
flow:dst2src_inter_time_avg|u_int64_t|dst2src_inter_time_avg
flow:dst2src_inter_time_min|u_int64_t|dst2src_inter_time_min
flow:dst2src_inter_time_max|u_int64_t|dst2src_inter_time_max
flow:dst2src_inter_time_std|u_int64_t|dst2src_inter_time_std
flow:src2dst_pay_bytes_avg|u_int64_t|src2dst_pay_bytes_avg
flow:src2dst_pay_bytes_min|u_int64_t|src2dst_pay_bytes_min
flow:src2dst_pay_bytes_max|u_int64_t|src2dst_pay_bytes_max
flow:src2dst_pay_bytes_std|u_int64_t|src2dst_pay_bytes_std
flow:dst2src_pay_bytes_avg|u_int64_t|dst2src_pay_bytes_avg
flow:dst2src_pay_bytes_min|u_int64_t|dst2src_pay_bytes_min
flow:dst2src_pay_bytes_max|u_int64_t|dst2src_pay_bytes_max
flow:dst2src_pay_bytes_std|u_int64_t|dst2src_pay_bytes_std
flow:dst2src_pay_bytes_rate|u_int64_t|dst2src_pay_bytes_rate
flow:src2dst_pay_bytes_rate|u_int64_t|src2dst_pay_bytes_rate
flow:dst2src_packets_rate|u_int64_t|dst2src_packets_rate
flow:src2dst_packets_rate|u_int64_t|src2dst_packets_rate
flow:inter_time_avg|u_int64_t|inter_time_avg
flow:inter_time_min|u_int64_t|inter_time_min
flow:inter_time_max|u_int64_t|inter_time_max
flow:inter_time_std|u_int64_t|inter_time_std
flow:payload_bytes_avg|u_int64_t|payload_bytes_avg
flow:payload_bytes_std|u_int64_t|payload_bytes_std
flow:payload_bytes_min|u_int64_t|payload_bytes_min
flow:payload_bytes_max|u_int64_t|payload_bytes_max
flow:src2dst_header_bytes_avg|u_int64_t|src2dst_header_bytes_avg
flow:src2dst_header_bytes_min|u_int64_t|src2dst_header_bytes_min
flow:src2dst_header_bytes_max|u_int64_t|src2dst_header_bytes_max
flow:src2dst_header_bytes_std|u_int64_t|src2dst_header_bytes_std
flow:dst2src_header_bytes_avg|u_int64_t|dst2src_header_bytes_avg
flow:dst2src_header_bytes_min|u_int64_t|dst2src_header_bytes_min
flow:dst2src_header_bytes_max|u_int64_t|dst2src_header_bytes_max
flow:dst2src_header_bytes_std|u_int64_t|dst2src_header_bytes_std
flow:packets_syn|u_int32_t|packets_syn
flow:packets_ack|u_int32_t|packets_ack
flow:packets_fin|u_int32_t|packets_fin
flow:packets_rst|u_int32_t|packets_rst
flow:packets_psh|u_int32_t|packets_psh
flow:packets_urg|u_int32_t|packets_urg
flow:tcp_retransmissions|u_int32_t|tcp_retransmissions
flow:payload_size_variation|u_int32_t|payload_size_variation
flow:window_scaling_variation|u_int32_t|window_scaling_variation
flow:C_number_of_contacts|u_int32_t|C_number_of_contacts
flow:C_src2dst_pay_bytes_avg|u_int64_t|C_src2dst_pay_bytes_avg
flow:C_src2dst_pay_bytes_min|u_int64_t|C_src2dst_pay_bytes_min
flow:C_src2dst_pay_bytes_max|u_int64_t|C_src2dst_pay_bytes_max
flow:C_src2dst_pay_bytes_std|u_int64_t|C_src2dst_pay_bytes_std
flow:C_src2dst_header_bytes_avg|u_int64_t|C_src2dst_header_bytes_avg
flow:C_src2dst_header_bytes_min|u_int64_t|C_src2dst_header_bytes_min
flow:C_src2dst_header_bytes_max|u_int64_t|C_src2dst_header_bytes_max
flow:C_src2dst_header_bytes_std|u_int64_t|C_src2dst_header_bytes_std
flow:C_src2dst_packets_avg|u_int64_t|C_src2dst_packets_avg
flow:C_src2dst_packets_min|u_int64_t|C_src2dst_packets_min
flow:C_src2dst_packets_max|u_int64_t|C_src2dst_packets_max
flow:C_src2dst_packets_std|u_int64_t|C_src2dst_packets_std
flow:C_dst2src_pay_bytes_avg|u_int64_t|C_dst2src_pay_bytes_avg
flow:C_dst2src_pay_bytes_min|u_int64_t|C_dst2src_pay_bytes_min
flow:C_dst2src_pay_bytes_max|u_int64_t|C_dst2src_pay_bytes_max
flow:C_dst2src_pay_bytes_std|u_int64_t|C_dst2src_pay_bytes_std
flow:C_dst2src_header_bytes_avg|u_int64_t|C_dst2src_header_bytes_avg
flow:C_dst2src_header_bytes_min|u_int64_t|C_dst2src_header_bytes_min
flow:C_dst2src_header_bytes_max|u_int64_t|C_dst2src_header_bytes_max
flow:C_dst2src_header_bytes_std|u_int64_t|C_dst2src_header_bytes_std
flow:C_dst2src_packets_avg|u_int64_t|C_dst2src_packets_avg
flow:C_dst2src_packets_min|u_int64_t|C_dst2src_packets_min
flow:C_dst2src_packets_max|u_int64_t|C_dst2src_packets_max
flow:C_dst2src_packets_std|u_int64_t|C_dst2src_packets_std
flow:C_packets_syn_avg|u_int64_t|C_packets_syn_avg
flow:C_packets_syn_min|u_int64_t|C_packets_syn_min
flow:C_packets_syn_max|u_int64_t|C_packets_syn_max
flow:C_packets_syn_std|u_int64_t|C_packets_syn_std
flow:C_packets_ack_avg|u_int64_t|C_packets_ack_avg
flow:C_packets_ack_min|u_int64_t|C_packets_ack_min
flow:C_packets_ack_max|u_int64_t|C_packets_ack_max
flow:C_packets_ack_std|u_int64_t|C_packets_ack_std
flow:C_packets_fin_avg|u_int64_t|C_packets_fin_avg
flow:C_packets_fin_min|u_int64_t|C_packets_fin_min
flow:C_packets_fin_max|u_int64_t|C_packets_fin_max
flow:C_packets_fin_std|u_int64_t|C_packets_fin_std
flow:C_packets_rst_avg|u_int64_t|C_packets_rst_avg
flow:C_packets_rst_min|u_int64_t|C_packets_rst_min
flow:C_packets_rst_max|u_int64_t|C_packets_rst_max
flow:C_packets_rst_std|u_int64_t|C_packets_rst_std
flow:C_packets_psh_avg|u_int64_t|C_packets_psh_avg
flow:C_packets_psh_min|u_int64_t|C_packets_psh_min
flow:C_packets_psh_max|u_int64_t|C_packets_psh_max
flow:C_packets_psh_std|u_int64_t|C_packets_psh_std
flow:C_packets_urg_avg|u_int64_t|C_packets_urg_avg
flow:C_packets_urg_min|u_int64_t|C_packets_urg_min
flow:C_packets_urg_max|u_int64_t|C_packets_urg_max
flow:C_packets_urg_std|u_int64_t|C_packets_urg_std
flow:C_tcp_retransmissions_avg|u_int64_t|C_tcp_retransmissions_avg
flow:C_tcp_retransmissions_min|u_int64_t|C_tcp_retransmissions_min
flow:C_tcp_retransmissions_max|u_int64_t|C_tcp_retransmissions_max
flow:C_tcp_retransmissions_std|u_int64_t|C_tcp_retransmissions_std
flow:C_dst2src_pay_bytes_rate_avg|u_int64_t|C_dst2src_pay_bytes_rate_avg
flow:C_dst2src_pay_bytes_rate_min|u_int64_t|C_dst2src_pay_bytes_rate_min
flow:C_dst2src_pay_bytes_rate_max|u_int64_t|C_dst2src_pay_bytes_rate_max
flow:C_dst2src_pay_bytes_rate_std|u_int64_t|C_dst2src_pay_bytes_rate_std
flow:C_src2dst_pay_bytes_rate_avg|u_int64_t|C_src2dst_pay_bytes_rate_avg
flow:C_src2dst_pay_bytes_rate_min|u_int64_t|C_src2dst_pay_bytes_rate_min
flow:C_src2dst_pay_bytes_rate_max|u_int64_t|C_src2dst_pay_bytes_rate_max
flow:C_src2dst_pay_bytes_rate_std|u_int64_t|C_src2dst_pay_bytes_rate_std
flow:C_dst2src_packets_rate_avg|u_int64_t|C_dst2src_packets_rate_avg
flow:C_dst2src_packets_rate_min|u_int64_t|C_dst2src_packets_rate_min
flow:C_dst2src_packets_rate_max|u_int64_t|C_dst2src_packets_rate_max
flow:C_dst2src_packets_rate_std|u_int64_t|C_dst2src_packets_rate_std
flow:C_src2dst_packets_rate_avg|u_int64_t|C_src2dst_packets_rate_avg
flow:C_src2dst_packets_rate_min|u_int64_t|C_src2dst_packets_rate_min
flow:C_src2dst_packets_rate_max|u_int64_t|C_src2dst_packets_rate_max
flow:C_src2dst_packets_rate_std|u_int64_t|C_src2dst_packets_rate_std
flow:C_duration_avg|u_int64_t|C_duration_avg
flow:C_duration_min|u_int64_t|C_duration_min
flow:C_duration_max|u_int64_t|C_duration_max
flow:C_duration_std|u_int64_t|C_duration_std
flow:C_idletime_avg|u_int64_t|C_idletime_avg
flow:C_idletime_min|u_int64_t|C_idletime_min
flow:C_idletime_max|u_int64_t|C_idletime_max
flow:C_idletime_std|u_int64_t|C_idletime_std
flow:flow_use_time|u_int64_t|flow_use_time
flow:flow_idle_time|u_int64_t|flow_idle_time
flow:response_rel_time|u_int32_t|response_rel_time
flow:detection_completed|u_int8_t|detection_completed
EOF`
do
namehbase=`echo $i | cut -d'|' -f1`
typec=`echo $i | cut -d'|' -f2`
namec=`echo $i | cut -d'|' -f3`
sizenamehbase=`echo $i | cut -d'|' -f1 | wc -c`
sizenamehbase=$(($sizenamehbase-1))

if [ $typec == "char" ]; then
  typecSIZE="strlen(flow->$namec)"
  ast="*"
  ecom=""
else
  typecSIZE="sizeof($typec)"
  ast=""
  ecom="&"
fi

if [ $typec == "char" ]; then
cat << EOF 
// $namec
mutation = g_object_new (TYPE_MUTATION, NULL);
mutation->column = g_byte_array_new ();
mutation->value  = g_byte_array_new ();
g_byte_array_append (mutation->column,(guint*)  "$namehbase", $sizenamehbase);
g_byte_array_append (mutation->value ,(guint*${ast}) ${ecom}flow->$namec,  $typecSIZE);
g_ptr_array_add (mutations, mutation);

EOF
else
cat << EOF 
// $namec  c=$ii
sprintf(text[c], "%d", flow->$namec);
mutation = g_object_new (TYPE_MUTATION, NULL);
mutation->column = g_byte_array_new ();
mutation->value  = g_byte_array_new ();
g_byte_array_append (mutation->column,(guint*) "$namehbase", $sizenamehbase);
g_byte_array_append (mutation->value ,(guint**) text[c], strlen(text[c]));
g_ptr_array_add (mutations, mutation);
c++;

EOF

ii=$(($ii+1))

fi

done

#u_int32_t inter_time[HOGZILLA_MAX_NDPI_FLOWS];
#u_int64_t packet_size[HOGZILLA_MAX_NDPI_FLOWS];

# bash Hogzilla_features.sh  > ../src/output-plugins/hogzilla/mutation_by_flow.c

