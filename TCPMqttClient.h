#ifndef __TCP_MQTT_CLIENT_H
#define __TCP_MQTT_CLIENT_H

#include "MqttClient.h"

class TCPMqttClient : public MqttClient {
public:
	TCPMqttClient() : MqttClient(&sock) {}
    nsapi_error_t open(NetworkInterface *net, const char* hostname, const uint16_t port);

private:
    TCPSocket sock;
};

#endif /* __TCP_MQTT_CLIENT_H */
