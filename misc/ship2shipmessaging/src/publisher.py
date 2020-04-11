import paho.mqtt.client as mqtt
topic = "sensors/altimeter/1"
if __name__ == "__main__":        
    client = mqtt.Client(protocol=mqtt.MQTTv311)
    client.connect(host="broker.hivemq.com", port=1883)              
    client.publish(topic=topic, payload="300 feet")