#ifndef __TCP_MQTT_CLIENT_H
#define __TCP_MQTT_CLIENT_H

#include "MqttClient.h"

class TCPMqttClient : public MqttClient {
public:
	TCPMqttClient() : MqttClient() {}
    nsapi_error_t open(NetworkInterface *net, const char* hostname, const uint16_t port);

protected:
    nsapi_size_or_error_t send(const void *data, nsapi_size_t len) { return sock.send(data, len); }
    nsapi_size_or_error_t recv(void *data, nsapi_size_t len) { return sock.recv(data, len); }

private:
    TCPSocket sock;
};

#endif /* __TCP_MQTT_CLIENT_H */
