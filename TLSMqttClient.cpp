#include "TLSMqttClient.h"
#include "mbed_trace.h"

#define TRACE_GROUP "MQTT_CLIENT_TLS"

nsapi_error_t TLSMqttClient::open(NetworkInterface *net, const char* hostname, const uint16_t port)
{
	nsapi_error_t ret = NSAPI_ERROR_OK;
    
	if (setup_cb)
	{
		ret = setup_cb(&sock);
		if (ret != NSAPI_ERROR_OK) 
		{
			tr_error("setup() failed ret = %d", ret);
			return ret;
		}
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

	tr_debug("Connected to \"mqtts://%s:%u\"", hostname, port);
	
	// register for notifications (only after connection)
	sock.sigio(callback(this, &TLSMqttClient::socket_event));
	
	return ret;
}
