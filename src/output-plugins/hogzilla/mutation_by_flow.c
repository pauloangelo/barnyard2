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

