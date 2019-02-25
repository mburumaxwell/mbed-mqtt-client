#ifndef __MQTT_TYPES_H
#define __MQTT_TYPES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	MQTT_PACKET_TYPE_CONNECT = 1,
	MQTT_PACKET_TYPE_CONNACK,
	MQTT_PACKET_TYPE_PUBLISH,
	MQTT_PACKET_TYPE_PUBACK,
	MQTT_PACKET_TYPE_PUBREC,
	MQTT_PACKET_TYPE_PUBREL,
	MQTT_PACKET_TYPE_PUBCOMP,
	MQTT_PACKET_TYPE_SUBSCRIBE,
	MQTT_PACKET_TYPE_SUBACK,
	MQTT_PACKET_TYPE_UNSUBSCRIBE,
	MQTT_PACKET_TYPE_UNSUBACK,
	MQTT_PACKET_TYPE_PINGREQ,
	MQTT_PACKET_TYPE_PINGRESP,
	MQTT_PACKET_TYPE_DISCONNECT
} mqtt_packet_type_t;

typedef struct {
	union {
		uint8_t whole;
		struct {
			uint8_t reserved : 1;
			uint8_t clean_session : 1;
			uint8_t will : 1;
			uint8_t will_qos : 2;
			uint8_t retain : 1;
			uint8_t password : 1;
			uint8_t username : 1; // should be bit 7
		} bits;
	} connect_flags;
} mqtt_connect_options_t;

#define MQTT_QOS_AT_MOST_ONCE						0x00
#define MQTT_QOS_AT_LEAST_ONCE						0x01
#define MQTT_QOS_EXACTLY_ONCE						0x02
#define MQTT_DELIVERY_FAILURE						0x80

typedef enum {
	MQTT_PACKET_DELIVERY_AT_MOST_ONCE	= MQTT_QOS_AT_MOST_ONCE,
	MQTT_PACKET_DELIVERY_AT_LEAST_ONCE	= MQTT_QOS_AT_LEAST_ONCE,
	MQTT_PACKET_DELIVERY_EXACTLY_ONCE	= MQTT_QOS_EXACTLY_ONCE,
} mqtt_packet_qos_t;

typedef union {
	uint8_t whole;
	struct {
		uint8_t				retain : 1;
		mqtt_packet_qos_t	qos : 2;
		uint8_t				dup : 1;
		mqtt_packet_type_t	packet_type : 4;
	} bits;
} mqtt_header_fixed_publish_t;

typedef union {
	uint8_t whole;
	struct {
		uint8_t				reserved : 4;
		mqtt_packet_type_t	packet_type : 4;
	} bits;
} mqtt_header_fixed_normal_t;

typedef struct {
	char *topic;
	char *message;
	uint8_t retain;
	mqtt_packet_qos_t qos;
} mqtt_will_options_t;

typedef struct {
	char *clientId;
	char *username;
	char *password;
	uint16_t keepAliveSeconds;
	uint8_t cleanSession;
	mqtt_will_options_t will;
} mqtt_packet_connect_t;

typedef enum {
	MQTT_PACKET_CONN_ACCEPTED						= 0x00,
	MQTT_PACKET_CONN_REFUSED_UNACCEPTABLE_VERSION	= 0x01,
	MQTT_PACKET_CONN_REFUSED_ID_REJECTED			= 0x02,
	MQTT_PACKET_CONN_REFUSED_SERVER_UNAVAIL			= 0x03,
	MQTT_PACKET_CONN_REFUSED_BAD_USERNAME_PASSWORD	= 0x04,
	MQTT_PACKET_CONN_REFUSED_NOT_AUTHORIZED			= 0x05,
	MQTT_PACKET_CONN_REFUSED_UNKNOWN
} mqtt_connect_returncode_t;

typedef struct {
	uint8_t sessionPresent;
	mqtt_connect_returncode_t code;
} mqtt_packet_connect_ack_t;

typedef struct {
	size_t	length;
	void*	content;
} mqtt_payload_t;

typedef struct {
	mqtt_packet_qos_t qos;
	uint8_t duplicate;
	uint8_t retain;
	char *topic;
	uint16_t topic_len;
	uint16_t id;
	mqtt_payload_t payload;
} mqtt_packet_publish_t;

 typedef struct {
 	uint16_t id;
 } mqtt_packet_publish_ack_t;

typedef enum {
	MQTT_PACKET_SUBSCRIBE_SUCCESS_QOS0	= MQTT_QOS_AT_MOST_ONCE,
	MQTT_PACKET_SUBSCRIBE_SUCCESS_QOS1	= MQTT_QOS_AT_LEAST_ONCE,
	MQTT_PACKET_SUBSCRIBE_SUCCESS_QOS2	= MQTT_QOS_EXACTLY_ONCE,
	MQTT_PACKET_SUBSCRIBE_FAILURE		= MQTT_DELIVERY_FAILURE,
} mqtt_subscribe_returncode_t;

typedef struct {
	char *topic;
	uint16_t topic_len;
	mqtt_packet_qos_t qos;
} mqtt_subscribe_request_t;

typedef struct {
	uint16_t id;
	mqtt_subscribe_request_t *requests;
	uint8_t requests_count;
} mqtt_packet_subscribe_t;

typedef struct {
	uint16_t id;
	uint8_t responses_count;
	mqtt_subscribe_returncode_t *responses;
} mqtt_packet_subscribe_ack_t;

typedef struct {
	char *topic;
	uint16_t topic_len;
} mqtt_unsubscribe_request_t;

typedef struct {
	uint16_t id;
	mqtt_unsubscribe_request_t *requests;
	uint8_t requests_count;
} mqtt_packet_unsubscribe_t;

typedef struct {
	uint16_t id;
} mqtt_packet_unsubscribe_ack_t;

#ifdef __cplusplus
}
#endif

#endif // __MQTT_TYPES_H
