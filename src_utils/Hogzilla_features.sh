#!/bin/bash

for i in `cat << EOF
flow:lower_ip|u_int32_t|lower_ip
flow:upper_ip|u_int32_t|upper_ip
flow:lower_name|char|lower_name
flow:upper_name|char|upper_name
flow:lower_port|u_int16_t|lower_port
flow:upper_port|u_int16_t|upper_port
flow:protocol|u_int8_t|protocol
flow:vlan_id|u_int16_t|vlan_id
flow:last_seen|u_int64_t|last_seen
flow:bytes|u_int64_t|bytes
flow:packets|u_int32_t|packets
flow:flow_duration|u_int64_t|flow_duration
flow:first_seen|u_int64_t|first_seen
flow:max_packet_size|u_int32_t|max_packet_size
flow:min_packet_size|u_int32_t|min_packet_size
flow:avg_packet_size|u_int32_t|avg_packet_size
flow:payload_bytes|u_int64_t|payload_bytes
flow:payload_first_size|u_int32_t|payload_first_size
flow:payload_avg_size|u_int32_t|payload_avg_size
flow:payload_min_size|u_int32_t|payload_min_size
flow:payload_max_size|u_int32_t|payload_max_size
flow:packets_without_payload|u_int32_t|packets_without_payload
flow:detection_completed|u_int8_t|detection_completed
flow:detected_protocol|u_int32_t|detected_protocol
flow:host_server_name|char|host_server_name
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

cat << EOF 
// $namec
mutation = g_object_new (TYPE_MUTATION, NULL);
mutation->column = g_byte_array_new ();
mutation->value  = g_byte_array_new ();
g_byte_array_append (mutation->column,(guint8*) "$namehbase", $sizenamehbase);
g_byte_array_append (mutation->value ,(guint8*${ast}) ${ecom}flow->$namec,  $typecSIZE);
g_ptr_array_add (mutations, mutation);

EOF

done

#u_int32_t inter_time[HOGZILLA_MAX_NDPI_FLOWS];
#u_int64_t packet_size[HOGZILLA_MAX_NDPI_FLOWS];

# bash Hogzilla_features.sh  > ../src/output-plugins/hogzilla/mutation_by_flow.c

