#ifndef __TLS_MQTT_CLIENT_H
#define __TLS_MQTT_CLIENT_H

#include "MqttClient.h"

class TLSMqttClient : public MqttClient {
public:
	TLSMqttClient() : MqttClient(&sock), setup_cb(NULL) { }

    nsapi_error_t open(NetworkInterface *net, const char* hostname, const uint16_t port);
	void setup(Callback<nsapi_error_t(TLSSocket*)> cb) { setup_cb = cb; }
	
private:
    TLSSocket sock;
	Callback<nsapi_error_t(TLSSocket*)> setup_cb;
};

#endif /* __TLS_MQTT_CLIENT_H */
