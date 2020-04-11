# Writeup [s2s messaging](README.md)

## Challenge Description
**Author: kristebo**

**Difficulty: easy**

**Category: misc** 


Intercepted ship to ship communication. Can you find the message?

[s2s.pcapng](uploads/s2s.pcapng).


<details><summary>Hint</summary><p> 

MQTT
</p></details>

## Writeup

The first step in solving this challenge is to open the file [s2s.pcapng](uploads/s2s.pcapng) in Wireshark.

We see that some of the packets are tagged as MQTT-packets. There are a lot of
different packets, but most of them are ordinary background traffic. MQTT
is the only one standing out.

You can right click on one of the MQTT-packets and choose "Follow" and then
"TCP-steam".

You can see some MQTT Publish Message packets, and
if you look at one of the messages you can see
that it contains JSON-encoded data. One of the values in the message
is encoded in Base64.
Decoding the Base64 gives you a PNG file, and the PNG file contains the flag:

```
TG20{THIS IS A SHIP 2 SHIP MESSAGE: Prepare your disk spce for boarding}
```
