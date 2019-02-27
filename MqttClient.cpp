#include "MqttClient.h"
#include "mbed_trace.h"

// ensure we have the tr_hex_dump function available
#ifndef tr_hex_dump
#define tr_hex_dump( ... )
#endif

#define TRACE_GROUP				"MQTT_CLIENT"
#define tr_send_fail(err)		tr_error("> Write to server : failed! send returned %d", err)
#define tr_send_success(len)	tr_debug("> Write to server : %d bytes written", len)
#define tr_recv_fail(err)		tr_error("< Read from server: failed! recv returned %d", err)
#define tr_recv_success(len)	tr_debug("< Read from server: %d bytes read", len)

#define MQTT_PROTOCOL_NAME			"MQTT"
#define MQTT_PROTOCOL_NAME_LEN		4
#define MQTT_PROTOCOL_LEVEL			4
#define STRING_LENGTH_SIZE			2
#define REMAINING_LENGTH_MAX_SIZE	4

#if MBED_CONF_MBED_TRACE_ENABLE
static const char * const mqtt_packet_type_str[15] =
{
	"UNDEFINED",
	"CONNECT",
	"CONNACK",
	"PUBLISH",
	"PUBACK",
	"PUBREC",
	"PUBREL",
	"PUBCOMP",
	"SUBSCRIBE",
	"SUBACK",
	"UNSUBSCRIBE",
	"UNSUBACK",
	"PINGREQ",
	"PINGRESP",
	"DISCONNECT"
};

static const char* mqtt_packet_type_to_str(mqtt_packet_type_t pkt_type)
{
	uint8_t i = pkt_type;
	if (i > 15 || i < 0) i = 0; // ensure within bounds
	return mqtt_packet_type_str[i];
}
#endif

uint8_t MqttClient::encode_remaining_length(uint8_t *dest, size_t len)
{
	uint8_t encoded, count = 0;
	do {
		encoded = len % 128;
		len /= 128;
		if (len > 0) encoded |= 128;
		dest[count++] = encoded;
	} while (len > 0);
	return count;
}

nsapi_size_or_error_t MqttClient::read_remaining_length(size_t *val)
{
	nsapi_size_or_error_t sz_or_err = 0;
	uint8_t b, len = 0, v = 0;
	int mul = 0;

	*val = 0;
	do {
		sz_or_err = recv(&b, 1);
		// if we did not get exactly one byte, return the error
		if(sz_or_err != 1) return sz_or_err;

		// set the value
		v = (b & 127); // remove the most significant bit used for signifying more data
		mul = len == 0 ? 1 : (len * 128);
		*val += (v * mul);
	} while ((++len < REMAINING_LENGTH_MAX_SIZE) && (b & 128)); // continue if byte signifies more data and the bytes read won't exceed

	return len;
}

nsapi_error_t MqttClient::connect(const char *clientid, const char *username, const char *password, uint16_t keep_alive_seconds, bool clean)
{
	mqtt_packet_connect_t packet;

	// clean packet
	memset(&packet, 0, sizeof(mqtt_packet_connect_t));

	packet.clientId           = (char *) clientid;
	packet.username           = (char *) username;
	packet.password           = (char *) password;
	packet.keep_alive_seconds = keep_alive_seconds;
	packet.clean_session      = clean ? 1 : 0;

	return connect(&packet);
}

nsapi_error_t MqttClient::connect(mqtt_packet_connect_t *packet)
{
	mqtt_connect_options_t options = { 0 };
	mqtt_header_fixed_normal_t fhdr = { 0 };
	size_t client_id_len, username_len = 0, password_len = 0, will_topic_len = 0, will_msg_len = 0;
	size_t variable_header_len, payload_len, variable_part_len, required_buf_len, remaining_length, len;
	nsapi_size_or_error_t sz_or_err;
	uint8_t *buf = NULL, *tdst = NULL;

	if (!(packet->clientId != NULL && (((client_id_len = strlen(packet->clientId))) > 0)))
		return NSAPI_ERROR_PARAMETER;

	// set flags
	options.connect_flags.bits.clean_session = packet->clean_session;
	options.connect_flags.bits.username      = (packet->username != NULL && ((username_len = strlen(packet->username)) > 0));
	options.connect_flags.bits.password	     = (packet->password != NULL && ((password_len = strlen(packet->password)) > 0));
	options.connect_flags.bits.will		     = (packet->will.topic != NULL && ((will_topic_len = strlen(packet->will.topic)) > 0));
	if (options.connect_flags.bits.will)
	{
		options.connect_flags.bits.will_qos  = packet->will.qos;
		options.connect_flags.bits.retain    = packet->will.retain;
	}

	// calculate the payload length
	payload_len = STRING_LENGTH_SIZE + client_id_len;
	if (options.connect_flags.bits.will)
	{
		will_msg_len = strlen(packet->will.message);
		payload_len += STRING_LENGTH_SIZE + will_topic_len + STRING_LENGTH_SIZE + will_msg_len;
	}
	if (options.connect_flags.bits.username) payload_len += STRING_LENGTH_SIZE + username_len;
	if (options.connect_flags.bits.password) payload_len += STRING_LENGTH_SIZE + password_len;

	// calculate the variable part length (its header and payload)
	variable_header_len = STRING_LENGTH_SIZE + MQTT_PROTOCOL_NAME_LEN + 4;
	variable_part_len = variable_header_len + payload_len;

	// calculate the total required length
	required_buf_len = sizeof(mqtt_header_fixed_normal_t) + variable_part_len;

	// create buffer to use and ensure allocated
	buf = (uint8_t *)malloc(required_buf_len);
	if (buf == NULL) return NSAPI_ERROR_NO_MEMORY;
	tdst = buf;

	// form the fixed header
	fhdr.bits.packet_type = MQTT_PACKET_TYPE_CONNECT;
	remaining_length = variable_part_len;

	// write the fixed header
	*tdst++ = (uint8_t)(fhdr.whole);
	tdst += encode_remaining_length(tdst, remaining_length);

	// write the protocol name length
	*tdst++ = (uint8_t)(MQTT_PROTOCOL_NAME_LEN >> 8);
	*tdst++ = (uint8_t)(MQTT_PROTOCOL_NAME_LEN);

	// write the protocol name
	memcpy(tdst, MQTT_PROTOCOL_NAME, MQTT_PROTOCOL_NAME_LEN);
	tdst += MQTT_PROTOCOL_NAME_LEN;

	// write the protocol level
	*tdst++ = (uint8_t)(MQTT_PROTOCOL_LEVEL);

	// write the connect flags
	memcpy(tdst, &options, sizeof(mqtt_connect_options_t));
	tdst += sizeof(mqtt_connect_options_t);

	// write the keep alive period (seconds)
	*tdst++ = (uint8_t)(packet->keep_alive_seconds >> 8);
	*tdst++ = (uint8_t)(packet->keep_alive_seconds);

	// write the client id length
	*tdst++ = (uint8_t)(client_id_len >> 8);
	*tdst++ = (uint8_t)(client_id_len);

	// write the client id
	memcpy(tdst, packet->clientId, client_id_len);
	tdst += client_id_len;

	// write the will if specified
	if(options.connect_flags.bits.will)
	{
		// write the will topic length
		*tdst++ = (uint8_t)(will_topic_len >> 8);
		*tdst++ = (uint8_t)(will_topic_len);

		// write the will topic
		memcpy(tdst, packet->will.topic, will_topic_len);
		tdst += will_topic_len;

		// write the will message length
		*tdst++ = (uint8_t)(will_msg_len >> 8);
		*tdst++ = (uint8_t)(will_msg_len);

		// write the will message
		memcpy(tdst, packet->will.message, will_msg_len);
		tdst += will_msg_len;
	}

	// write username if specified
	if(options.connect_flags.bits.username)
	{
		// write the username length
		*tdst++ = (uint8_t)(username_len >> 8);
		*tdst++ = (uint8_t)(username_len);

		// write the username
		memcpy(tdst, packet->username, username_len);
		tdst += username_len;
	}

	// write password if specified
	if(options.connect_flags.bits.password)
	{
		// write the password length
		*tdst++ = (uint8_t)(password_len >> 8);
		*tdst++ = (uint8_t)(password_len);

		// write the password
		memcpy(tdst, packet->password, password_len);
		tdst += password_len;
	}

	len = tdst - buf; // calculate the length

	sz_or_err = send(buf, len);
	if (sz_or_err <= 0)
	{
		tr_send_fail(sz_or_err);
		free(buf);
		return sz_or_err;
	}

	tr_send_success(len);
	tr_hex_dump(buf, len);
	free(buf);
	return sz_or_err;
}

nsapi_error_t MqttClient::disconnect()
{
	nsapi_size_or_error_t sz_or_err;
	mqtt_header_fixed_normal_t fhdr = { 0 };

	// form the header
	fhdr.bits.packet_type = MQTT_PACKET_TYPE_DISCONNECT;

	// write the fixed header
    uint8_t buf[2] = { fhdr.whole, 0 }; // fixed header and 0 remaining length
	
    sz_or_err = send(buf, 2);
	if (sz_or_err <= 0)
	{
		tr_send_fail(sz_or_err);
		return sz_or_err;
	}

	tr_send_success(2);
	tr_hex_dump(buf, 2);
	return sz_or_err;
}

nsapi_error_t MqttClient::ping()
{
	nsapi_size_or_error_t sz_or_err;
	mqtt_header_fixed_normal_t fhdr = { 0 };
	
	// form the header
	fhdr.bits.packet_type = MQTT_PACKET_TYPE_PINGREQ;

	// write the fixed header
    uint8_t buf[2] = { fhdr.whole, 0 }; // fixed header and 0 remaining length
	
    sz_or_err = send(buf, 2);
	if (sz_or_err <= 0)
	{
		tr_send_fail(sz_or_err);
		return sz_or_err;
	}

	tr_send_success(2);
	tr_hex_dump(buf, 2);
	return sz_or_err;
}

nsapi_error_t MqttClient::publish(const char *topic, const uint16_t packet_id, const uint8_t* p, const nsapi_size_t plen)
{
	mqtt_packet_publish_t packet;
	const mqtt_packet_qos_t qos = MQTT_PACKET_DELIVERY_AT_LEAST_ONCE;

	// clean packet
	memset(&packet, 0, sizeof(mqtt_packet_publish_t));
	
	packet.duplicate         = 0;               // the DUP (duplicate) flag
	packet.id                = packet_id;       // the packet id
	packet.qos               = qos;             // the QoS (quality of service) flag
	packet.retain            = 0;               // the retained flag
	packet.topic             = (char *)topic;   // the topic
	packet.topic_len         = strlen(topic);   // the topic length
	packet.payload.content   = (void *)p;       // the payload
	packet.payload.length    = plen;            // the payload length
	
    return publish(&packet);
}

nsapi_error_t MqttClient::publish(mqtt_packet_publish_t *packet)
{
	nsapi_size_or_error_t sz_or_err;
	mqtt_header_fixed_publish_t fhdr = { 0 };
	size_t variable_header_len, variable_part_len, required_buf_len, remaining_length, len;
	uint8_t *buf = NULL, *tdst = NULL;

	if (packet->topic == NULL || (strlen(packet->topic) != packet->topic_len)
		|| packet->payload.content == NULL || packet->payload.length <= 0)
	{
		return NSAPI_ERROR_PARAMETER;
	}

	// calculate lengths
	variable_header_len = STRING_LENGTH_SIZE
						+ packet->topic_len
						+ (packet->qos > MQTT_PACKET_DELIVERY_AT_MOST_ONCE ? sizeof(packet->id) : 0);

	variable_part_len = variable_header_len + packet->payload.length;

	// calculate the total required length
	required_buf_len = sizeof(mqtt_header_fixed_normal_t) + variable_part_len;

	// create buffer to use and ensure allocated
	buf = (uint8_t *)malloc(required_buf_len);
	if (buf == NULL) return NSAPI_ERROR_NO_MEMORY;
	tdst = buf;
	
	// form the fixed header
	fhdr.bits.dup           = packet->duplicate;
	fhdr.bits.retain        = packet->retain;
	fhdr.bits.qos           = packet->qos;
	fhdr.bits.packet_type   = MQTT_PACKET_TYPE_PUBLISH;
	remaining_length        = variable_part_len;

	// write the fixed header
    *(tdst++) = fhdr.whole;
	tdst += encode_remaining_length(tdst, remaining_length);
	
	// write the topic length
	*tdst++ = (uint8_t)(packet->topic_len >> 8);
	*tdst++ = (uint8_t)(packet->topic_len);
	
	// write the topic
	memcpy(tdst, packet->topic, packet->topic_len);
	tdst += packet->topic_len;

	// write packet id if required
	if(packet->qos > MQTT_PACKET_DELIVERY_AT_MOST_ONCE)
	{
		*tdst++ = (uint8_t)(packet->id >> 8);
		*tdst++ = (uint8_t)(packet->id);
	}

	len = tdst - buf; // calculate the length

	sz_or_err = send(buf, len);
	if (sz_or_err <= 0)
	{
		tr_send_fail(sz_or_err);
		return sz_or_err;
	}

	tr_send_success(len);
	tr_hex_dump(buf, len);

	// now send the payload
    sz_or_err = send(packet->payload.content, packet->payload.length);
	if (sz_or_err <= 0)
	{
		tr_send_fail(sz_or_err);
		free(buf);
		return sz_or_err;
	}

	tr_send_success(packet->payload.length);
	tr_hex_dump(packet->payload.content, packet->payload.length);
	free(buf);
	return sz_or_err;
}

nsapi_error_t MqttClient::publish_ack(const uint16_t packet_id)
{
	mqtt_packet_publish_ack_t packet = { 0 };
	packet.id = packet_id;
	
	return publish_ack(&packet);
}

nsapi_error_t MqttClient::publish_ack(mqtt_packet_publish_ack_t *packet)
{
	nsapi_size_or_error_t sz_or_err;
	mqtt_header_fixed_normal_t fhdr = { 0 };
	
	// form the header
	fhdr.bits.packet_type = MQTT_PACKET_TYPE_PUBACK;
	
	// write the fixed header and 2 remaining length
    uint8_t buf[4] = {
		fhdr.whole,
		2,
		(uint8_t)(packet->id >> 8),
		(uint8_t)(packet->id)
	};
	
    sz_or_err = send(buf, 4);
	if (sz_or_err <= 0)
	{
		tr_send_fail(sz_or_err);
		return sz_or_err;
	}

	tr_send_success(4);
	tr_hex_dump(buf, 4);
	return sz_or_err;
}

nsapi_error_t MqttClient::subscribe(const char *topic, const uint16_t packet_id)
{
	mqtt_subscribe_request_t req;
	
	// clean request
	memset(&req, 0, sizeof(mqtt_subscribe_request_t));
    
	req.topic     = (char *)topic;
	req.topic_len = strlen(topic);
	req.qos       = MQTT_PACKET_DELIVERY_AT_LEAST_ONCE;
	
	return subscribe(&req, 1, packet_id);
}

nsapi_error_t MqttClient::subscribe(mqtt_subscribe_request_t* requests, const uint8_t count, const uint16_t packet_id)
{
	mqtt_packet_subscribe_t packet;

	// clean packet
	memset(&packet, 0, sizeof(mqtt_packet_subscribe_t));
    
	packet.id               = packet_id;
	packet.requests         = requests;
	packet.requests_count   = count;

	return subscribe(&packet);
}

nsapi_error_t MqttClient::subscribe(mqtt_packet_subscribe_t *packet)
{
	mqtt_header_fixed_normal_t fhdr = { 0 };
	size_t payload_len, variable_header_len, variable_part_len, required_buf_len, remaining_length, len;
	nsapi_size_or_error_t sz_or_err;
	uint8_t *buf = NULL, *tdst = NULL, i;

	if (packet->requests_count <= 0 || packet->requests == NULL) return NSAPI_ERROR_PARAMETER;

	payload_len = 0;
	for (i = 0; i < packet->requests_count; i++) 
	{
		payload_len += STRING_LENGTH_SIZE + packet->requests[i].topic_len + 1;// length, value, QoS
	}

	// calculate lengths
	variable_header_len = sizeof(packet->id);// the SUBSCRIBE packet has a fixed variable header with a packet ID
	variable_part_len = variable_header_len + payload_len;

	// calculate the total required length
	required_buf_len = sizeof(mqtt_header_fixed_normal_t) + variable_part_len;

	// create buffer to use and ensure allocated
	buf = (uint8_t *)malloc(required_buf_len);
	if (buf == NULL) return NSAPI_ERROR_NO_MEMORY;
	tdst = buf;
	
	// form the header
	fhdr.bits.packet_type = MQTT_PACKET_TYPE_SUBSCRIBE;
	fhdr.bits.reserved = 0x02; // sec protocol section 3.8.1
	remaining_length = variable_part_len;

	// write the fixed header
	*tdst++ = (uint8_t)(fhdr.whole);
	tdst += encode_remaining_length(tdst, remaining_length);

	// write the packet id
	*tdst++ = (uint8_t)(packet->id >> 8);
	*tdst++ = (uint8_t)(packet->id);

	// write each topic
	for(i = 0 ; i < packet->requests_count ; i++)
	{
		// write the topic length
		*tdst++ = (uint8_t)(packet->requests[i].topic_len >> 8);
		*tdst++ = (uint8_t)(packet->requests[i].topic_len);

		// write the topic
		memcpy(tdst, packet->requests[i].topic, packet->requests[i].topic_len);
		tdst += packet->requests[i].topic_len;

		// write the QoS
		*tdst++ = (uint8_t)packet->requests[i].qos;
	}

	len = tdst - buf; // calculate the length
    sz_or_err = send(buf, len);
	if (sz_or_err <= 0)
	{
		tr_send_fail(sz_or_err);
		free(buf);
		return sz_or_err;
	}

	tr_send_success(len);
	tr_hex_dump(buf, len);
	free(buf);
	return sz_or_err;
}

nsapi_error_t MqttClient::unsubscribe(const char *topic, const uint16_t packet_id)
{
	mqtt_unsubscribe_request_t req;
	
	// clean packet
	memset(&req, 0, sizeof(mqtt_unsubscribe_request_t));
    
	req.topic     = (char *)topic;
	req.topic_len = strlen(topic);
	
	return unsubscribe(&req, 1, packet_id);
}

nsapi_error_t MqttClient::unsubscribe(mqtt_unsubscribe_request_t* requests, const uint8_t count, const uint16_t packet_id)
{
	mqtt_packet_unsubscribe_t packet;

	// clean packet
	memset(&packet, 0, sizeof(mqtt_packet_unsubscribe_t));
    
	packet.id               = packet_id;
	packet.requests         = requests;
	packet.requests_count   = count;

	return unsubscribe(&packet);
}

nsapi_error_t MqttClient::unsubscribe(mqtt_packet_unsubscribe_t *packet)
{
	mqtt_header_fixed_normal_t fhdr = { 0 };
	size_t payload_len, variable_header_len, variable_part_len, required_buf_len, remaining_length, len;
	nsapi_size_or_error_t sz_or_err;
	uint8_t *buf = NULL, *tdst = NULL, i;

	if (packet->requests_count <= 0 || packet->requests == NULL) return NSAPI_ERROR_PARAMETER;

	payload_len = 0;
	for (i = 0; i < packet->requests_count; i++) 
	{
		payload_len += STRING_LENGTH_SIZE + packet->requests[i].topic_len;// length, value
	}

	// calculate lengths
	variable_header_len = sizeof(packet->id);// the SUBSCRIBE packet has a fixed variable header with a packet ID
	variable_part_len = variable_header_len + payload_len;

	// calculate the total required length
	required_buf_len = sizeof(mqtt_header_fixed_normal_t) + variable_part_len;

	// create buffer to use and ensure allocated
	buf = (uint8_t *)malloc(required_buf_len);
	if (buf == NULL) return NSAPI_ERROR_NO_MEMORY;
	tdst = buf;

	// form the header
	fhdr.bits.packet_type = MQTT_PACKET_TYPE_UNSUBSCRIBE;
	fhdr.bits.reserved = 0x02; // see protocol section 3.10.1
	remaining_length = variable_part_len;

	// write the fixed header
	*tdst++ = (uint8_t)(fhdr.whole);
	tdst += encode_remaining_length(tdst, remaining_length);

	// write the packet id
	*tdst++ = (uint8_t)(packet->id >> 8);
	*tdst++ = (uint8_t)(packet->id);

	// write each topic
	for(i = 0 ; i < packet->requests_count ; i++)
	{
		// write the topic length
		*tdst++ = (uint8_t)(packet->requests[i].topic_len >> 8);
		*tdst++ = (uint8_t)(packet->requests[i].topic_len);

		// write the topic
		memcpy(tdst, packet->requests[i].topic, packet->requests[i].topic_len);
		tdst += packet->requests[i].topic_len;
	}

	len = tdst - buf; // calculate the length
    sz_or_err = send(buf, len);
	if (sz_or_err <= 0)
	{
		tr_send_fail(sz_or_err);
		free(buf);
		return sz_or_err;
	}

	tr_send_success(len);
	tr_hex_dump(buf, len);
	free(buf);
	return sz_or_err;
}

nsapi_error_t MqttClient::do_work()
{
	uint8_t fhdr_w, *bf, *pl_raw = NULL;
	mqtt_header_fixed_normal_t fhdr = { 0 };
	size_t bf_sz, rem_len;
	nsapi_size_or_error_t sz_or_err;

	// try read the type byte
	// would block response means there is no data, so wait for later, if zero (signal close) or less, close the underlying network
	sz_or_err = recv(&fhdr_w, 1);
	if (sz_or_err == NSAPI_ERROR_WOULD_BLOCK) return NSAPI_ERROR_WOULD_BLOCK;
	else if (sz_or_err <= 0)
	{
		tr_recv_fail(sz_or_err);
		// TODO: implement closing the underlying network and preventing it from being used again
		// close();
		return sz_or_err;
	}

	// at this point we have the fixed header byte 1 (type) so we can then read the remaining length
	sz_or_err = read_remaining_length(&rem_len);
	if (sz_or_err <= 0)
	{
		tr_recv_fail(sz_or_err);
		// TODO: implement closing the underlying network and preventing it from being used again
		// close();
		return sz_or_err;
	}

	// get memory to store the payload and clean it
	bf_sz = 1 + sz_or_err + rem_len;
	bf = (uint8_t *)malloc(bf_sz);
	if (!bf) return NSAPI_ERROR_NO_MEMORY;
	memset(bf, 0, bf_sz);

	// write the already read bytes into the buffer
	bf[0] = fhdr_w;
	encode_remaining_length(&(bf[1]), rem_len);
	pl_raw = bf + 1 + sz_or_err; // skip the already read bytes

	// only read if there is a remaining length
	if(rem_len > 0)
	{
		// read the remaining data into created buffer
		sz_or_err = recv(pl_raw, rem_len);
		if (sz_or_err <= 0)
		{
			tr_recv_fail(sz_or_err);
			// TODO: implement closing the underlying network and preventing it from being used again
			// close();
			free(bf);
			return sz_or_err;
		}
	}

	tr_recv_success(bf_sz);
	tr_hex_dump(bf, bf_sz);

	// at this point, we have all the data so we can begin decoding the buffer
	fhdr.whole = fhdr_w;
	tr_debug("Received %s (%02x) packet", mqtt_packet_type_to_str(fhdr.bits.packet_type), fhdr.bits.packet_type);

	switch (fhdr.bits.packet_type)
	{
	default:
		tr_error("Packet type (%02x) not handled", fhdr.bits.packet_type);
		break;
	case MQTT_PACKET_TYPE_CONNACK:
		if (packet_received_cb)
		{
			mqtt_packet_connect_ack_t con_ack;
			memset(&con_ack, 0, sizeof(mqtt_packet_connect_ack_t));
			con_ack.session_present = (pl_raw[0] & 0x01);
			con_ack.code = (mqtt_connect_returncode_t)pl_raw[1];
			packet_received_cb(MQTT_PACKET_TYPE_CONNACK, &con_ack);
		}
		break;
	case MQTT_PACKET_TYPE_PINGRESP:
		if (packet_received_cb)
		{
			packet_received_cb(MQTT_PACKET_TYPE_PINGRESP, NULL);
		}
		break;
	case MQTT_PACKET_TYPE_PUBACK:
		if (packet_received_cb)
		{
			mqtt_packet_publish_ack_t pub_ack;
			memset(&pub_ack, 0, sizeof(mqtt_packet_publish_ack_t));
			pub_ack.id = ((pl_raw[0] << 8) | pl_raw[1]);
			packet_received_cb(MQTT_PACKET_TYPE_PUBACK, &pub_ack);
		}
		break;
	case MQTT_PACKET_TYPE_SUBACK:
		if (packet_received_cb)
		{
			mqtt_packet_subscribe_ack_t sub_ack;
			memset(&sub_ack, 0, sizeof(mqtt_packet_subscribe_ack_t));
			sub_ack.id = ((pl_raw[0] << 8) | pl_raw[1]);
			sub_ack.responses_count = (rem_len - 2); // remove count for the packet id
			sub_ack.responses = new mqtt_subscribe_returncode_t[sub_ack.responses_count];
			if (sub_ack.responses)
			{
				for (uint8_t i = 0; i < sub_ack.responses_count; i++)
				{
					sub_ack.responses[i] = (mqtt_subscribe_returncode_t)(pl_raw[i + 2]); // offset bytes used by packet id
				}
				packet_received_cb(MQTT_PACKET_TYPE_SUBACK, &sub_ack);
				free(sub_ack.responses);
			}
		}
		break;
	case MQTT_PACKET_TYPE_UNSUBACK:
		if (packet_received_cb)
		{
			mqtt_packet_unsubscribe_ack_t unsub_ack;
			memset(&unsub_ack, 0, sizeof(mqtt_packet_unsubscribe_ack_t));
			unsub_ack.id = ((pl_raw[0] << 8) | pl_raw[1]);
			packet_received_cb(MQTT_PACKET_TYPE_UNSUBACK, &unsub_ack);
		}
		break;
	case MQTT_PACKET_TYPE_PUBLISH:
		mqtt_packet_publish_t pub;
		mqtt_header_fixed_publish_t *fhdr_pub = (mqtt_header_fixed_publish_t *)(&fhdr);
		memset(&pub, 0, sizeof(mqtt_packet_publish_t));
		pub.duplicate    = fhdr_pub->bits.dup;
		pub.retain       = fhdr_pub->bits.retain;
		pub.qos          = fhdr_pub->bits.qos;
		
		uint8_t *pub_buf = pl_raw;
		
		// read the topic length and set the topic address
		pub.topic_len = (*pub_buf++) << 8;
		pub.topic_len |= *pub_buf++;
		pub.topic = (char *)pub_buf;
		pub_buf += pub.topic_len;
		
		// set the packet id if required
		if (pub.qos > MQTT_PACKET_DELIVERY_AT_MOST_ONCE)
		{
			pub.id = (*pub_buf++) << 8;
			pub.id |= *pub_buf++;
		}
		
		// set the payload
		pub.payload.length = rem_len - (pub_buf - pl_raw);
		pub.payload.content = pub_buf;
		
		// make the callback if available
		if(packet_received_cb)
		{
			packet_received_cb(MQTT_PACKET_TYPE_PUBLISH, &pub);
		}
		break;
	}

	free(bf);
	return bf_sz;
}

void MqttClient::packet_received(Callback<void(mqtt_packet_type_t, void*)> cb)
{
	packet_received_cb = cb;
}
