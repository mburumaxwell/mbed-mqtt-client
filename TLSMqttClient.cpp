#include "TLSMqttClient.h"
#include "mbed_trace.h"

#define TRACE_GROUP "MQTT_CLIENT_TLS"

nsapi_error_t TLSMqttClient::open(NetworkInterface *net, const char* hostname, const uint16_t port)
{
    nsapi_error_t ret = NSAPI_ERROR_OK;
    
    if (_root_ca_pem != NULL)
    {
        ret = sock.set_root_ca_cert(_root_ca_pem);
        if (ret != NSAPI_ERROR_OK) 
        {
            tr_error("socket.set_root_ca_cert() failed ret = %d", ret);
            return ret;
        }
    }

    if (setup_cb)
    {
        setup_cb(&sock);
    }

    ret = sock.open(net);
    if (ret != NSAPI_ERROR_OK) 
    {
        tr_error("socket.open() failed ret = %d", ret);
        return ret;
    }
    
    ret = sock.connect(hostname, port);
    if (ret != NSAPI_ERROR_OK) 
    {
	    tr_error("socket.connect() failed ret = %d\n", ret);
        return ret;
    }

    tr_debug("Connected to \"mqtt://%s:%u\"", hostname, port);    
    return ret;
}
