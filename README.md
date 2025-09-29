# efergy_rxfwd

An HTTP server for receiving calls from the Efergy Hub.

## Quick History

The Efergy Engage platform is scheduled to be decommisioned by 01/01/2026 along
with all associated Energyhive websites.

The Efergy Engage Hub Solo is a small device that receives energy measurements
from Efergy sensors via RF (433Mhz) and forward them to the Engage platform,
where the user can navigate instant and historical data.

https://github.com/aarond10/powermeter_hub_server is able to intercept those
calls and store them locally, but hasn't changed in many years. To make it work
one needs to get Python to use a version of OpenSSL with support for SSLv3
(which is unsafe).

### Redirecting Efergy Hub calls

There are two possible approaches:

  - connect a device to the Hub in order to intercept the calls via 'iptables'.
    This could be a Raspberry Pi, in which case the HTTP server can be running
    on the same device.
  - configure a local DNS server to resolve all of \*.sensornet.info to a local
    device, where the HTTP server is running:

In both cases, note that the calls are intended for port 443 so you either need
the server to run as root or you need to further forward them to, say, port
8080:
```
     sudo iptables -t nat -A PREROUTING \
          -p tcp -s 192.168.1.125 --dport 443 -j REDIRECT --to-port 8080
```

### Cross-compiling for the Raspberry Pi Zero 2W

The src directory includes a proof-of-concept C++ program that can be compiled
and linked against a local libssl to receive the calls and store them locally.
The included build instructions aim for a Raspberry Pi Zero 2w deployment.

The important detail here is that the Hub makes HTTPS calls using SSLv3, which
is unsafe and not recommended in any other scenario, so we will need a version
of OpenSSL that enables SSLv3. (Note that the Efergy Engage endpoint also only
support SSLv3, so regular wget calls won't work)

Here are quick notes about cross-compiling on linux:
  - Install the compiler:
```
    sudo apt install g++-14-arm-linux-gnueabihf
```
  - compile (with support for SSLv3) and install libssl 1.1. Once you download
    and unpack, here are the commands to build and install in /opt/arm/openssl
```
     ./Configure --prefix=/opt/arm/openssl --openssldir=/opt/arm/openssl \
        --cross-compile-prefix=arm-linux-gnueabihf- CC=gcc-14 linux-armv4 \
        enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers
     make clean
     make
     make install_sw
```
   - build with the included Makefile (which only works for TARGET=arm)
```
     make
```

### Tentative documentation of the Efergy Protocol

- Upon startup the Hub makes a GET request for /check_key.html. Answering with
  200 OK is enough.
- Occasionally the Hub makes a POST request to /h3 with
  Content-Type:application/eh-ping. Again, answering with 200 OK is enough.
- Every few seconds ther is a POST to /h3 with Content-type:application/eh-data.
  Each row in the body of the request contains the data for a single sensor.
- After being unable to reach its counterpart for a while, the Hub makes a
  series of POST requests to /h3bulk, with Content-type:application/eh-datalog.
  Each requests has 4096 bytes in its body. Here's the description of the
  contents:
    - First 32 bits are a timestamp, presumably the first moment data
      transmission failed. Sensor data in the file will be relative to this
      initial timestamp.
```
3177 d668 -> 1752004401
```
    - A list of sensor IDs follow. The Hub can support at most 5 sensors and
      it seems like the datalog has 5 24-bit slots for the IDs:
```
18 15 0a  -> 0xA1518 sensor 660760
26 17 0a  -> 0xA1726 sensor 661286
b2 e7 0c  -> 0xCE7B2 sensor 845746
00 00 00
00 00 00
```
       References to the sensors in the data below will be made using 5 bits,
       so: 0x01, 0x02, 0x04, 0x08 and 0x10

     - Then the actual data. It starts with 3 bits declaring the type of sensor,
       which in turn defines how many bits are part of the data:
        - An EFCT sensor (type 0x1) includes 64 bits of data: the type itself, a
          reference to a sensor ID, a time offset, one float and a checksum:

```
Data: 24 00dc e0dc dd46 df
    - 3 bits: 001 -> EFCT sensor
    - 5 bits: 00100 -> reference to the third sensor ID
    - 1 bit: presumably to be prepended to the time-offset below, but not sure.
    - 16 bits: 0x00dc: time offset -> 220 seconds after file timestamp
    - 32 bits: float (P1) e0dc dd46 -> 0x46DDDCE0 -> 28398.4375
    - 8 bits: 0xdf checksum as sum of bytes MOD 256:
         0x24 + 0x00 + 0xdc + 0xe0 + 0xdc + 0xdd + 0x46
           36 +    0 +  220 +  224 +  220 +  221 +   70
         = 991 -> (MOD 256) -> 223 -> 0xdf
```

        - An EFMS1 sensor (type 0x2) includes 128 bits of data: the type itself,
          a reference to a sensor ID, a time offset, three floats and a checksum:

```
  62 10ed 44ed ec43 77d2 d241 9d7d a4fd c6
    - 3 bits: 011 -> EFMS1 sensor
    - 5 bits: 00010 -> reference to the second sensor ID
    - 1 bit: presumably to be prepended to the time-offset below, but not sure.
    - 16 bits: 0x10ed: time offset -> 4333 seconds after file timestamp
    - 32-bit float (M): 44ed ec43 -> 473.85
    - 32-bit float (T): 77d2 d241 -> 26.35
    - 32-bit float (L): 9d7d a4fd -> -27330701594293853740255903705697615872
    - and checksum, as above
```

        - An end-of-data signal (type 0xF)

