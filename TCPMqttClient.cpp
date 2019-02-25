#include "TCPMqttClient.h"
#include "mbed_trace.h"

#define TRACE_GROUP "MQTT_CLIENT_TCP"

nsapi_error_t TCPMqttClient::open(NetworkInterface *net, const char* hostname, const uint16_t port)
{
	sock.set_blocking(false);
	
    nsapi_error_t ret = sock.open(net);
    if (ret != NSAPI_ERROR_OK) 
    {
        tr_error("socket.open() failed ret = %d", ret);
        return ret;
    }
    
    ret = sock.connect(hostname, port);
    if (ret != NSAPI_ERROR_OK) 
    {
	    tr_error("socket.connect() failed ret = %d", ret);
        return ret;
    }

    tr_debug("Connected to \"mqtt://%s:%u\"", hostname, port);    
    return ret;
}

