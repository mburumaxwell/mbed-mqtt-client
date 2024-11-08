#ifndef __MQTT_CLIENT_H
#define __MQTT_CLIENT_H

#include <mbed.h>
#include "nsapi_types.h"
#include "mqtt_types.h"

class MqttClient {
public:
	MqttClient(Socket *socket);
	
    virtual nsapi_error_t open(NetworkInterface *net, const char* hostname, const uint16_t port) = 0;

	nsapi_error_t connect(const char *clientid, const char *username, const char *password, uint16_t keep_alive_seconds = 0, bool clean = false);
	nsapi_error_t connect(mqtt_packet_connect_t *packet);

	nsapi_error_t disconnect();
	nsapi_error_t ping();

	nsapi_error_t publish(const char *topic, const uint16_t packet_id, const uint8_t* p, const nsapi_size_t plen);
	nsapi_error_t publish(mqtt_packet_publish_t *packet);

	nsapi_error_t publish_ack(const uint16_t packet_id);
	nsapi_error_t publish_received(const uint16_t packet_id);
	nsapi_error_t publish_release(const uint16_t packet_id);
	nsapi_error_t publish_complete(const uint16_t packet_id);

	nsapi_error_t subscribe(const char *topic, const uint16_t packet_id);
	nsapi_error_t subscribe(mqtt_subscribe_request_t* requests, const uint8_t count, const uint16_t packet_id);
	nsapi_error_t subscribe(mqtt_packet_subscribe_t *packet);

	nsapi_error_t unsubscribe(const char *topic, const uint16_t packet_id);
	nsapi_error_t unsubscribe(mqtt_unsubscribe_request_t* requests, const uint8_t count, const uint16_t packet_id);
	nsapi_error_t unsubscribe(mqtt_packet_unsubscribe_t *packet);

	nsapi_error_t process_events();
	
	void packet_received(Callback<void(MqttClient*, mqtt_packet_type_t, void*)> cb);

	void on_events_to_process(Callback<void(MqttClient*)> cb) { on_events_to_process_cb = cb; }

protected:
	virtual void socket_event();
	
private:
	uint8_t encode_remaining_length(uint8_t *dest, size_t len);
	nsapi_size_or_error_t read_remaining_length(size_t *val);

private:
	Socket *_socket;
	Callback<void(MqttClient*, mqtt_packet_type_t, void*)> packet_received_cb;
	Callback<void(MqttClient*)> on_events_to_process_cb;
};

#endif /* __MQTT_CLIENT_H */
