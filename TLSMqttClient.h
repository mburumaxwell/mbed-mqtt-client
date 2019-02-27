#ifndef __TLS_MQTT_CLIENT_H
#define __TLS_MQTT_CLIENT_H

#include "MqttClient.h"

class TLSMqttClient : public MqttClient {
public:
    TLSMqttClient() : MqttClient() { }

    nsapi_error_t open(NetworkInterface *net, const char* hostname, const uint16_t port);

	void setup(Callback<nsapi_error_t(TLSSocket*)> cb) { setup_cb = cb; }


protected:
    nsapi_size_or_error_t send(const void *data, nsapi_size_t len) { return sock.send(data, len); }
    nsapi_size_or_error_t recv(void *data, nsapi_size_t len) { return sock.recv(data, len); }

private:
    TLSSocket sock;
	Callback<nsapi_error_t(TLSSocket*)> setup_cb;
};

#endif /* __TLS_MQTT_CLIENT_H */
