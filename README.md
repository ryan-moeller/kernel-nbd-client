# FreeBSD GEOM NBD Client

This is a Network Block Device (NBD) client for the FreeBSD kernel GEOM
framework.

The project consists of a kernel driver for the NBD GEOM class in mod/ and a
user library for the geom(8) control utility in lib/.

## Features

This client supports the following noteworthy features:

* Established connections are handed off to the kernel, allowing reroot onto the
  network-backed devices.
* Supports using multiple connections to the NBD server to parallelize commands.
* Supports optional TLS encryption using ktls(4).
* It is fast - zero copies are performed where possible.

## Building and Installing

To build and install for a production kernel:

```
# make
# make install
```

To build for a debug kernel with INVARIANTS:

```
# make DEBUG_FLAGS="-g -O0 -DWITNESS -DINVARIANTS"
# make install
```

## Usage

With the driver and library installed, connect to an NBD server running on the
host `nbdserver`:

```
# gnbd connect nbdserver
nbd0
```

Increase the number of connections used for the device `nbd0`:

```
# gnbd scale -c 8 nbd0
```

Display information about the device `nbd0`:

```
# gnbd list nbd0
Geom name: nbd0
Connections: 8
TLS: no
MaximumPayload: 262144
PreferredBlocksize: 4096
MinimumBlocksize: 512
TransmissionFlags: HAS_FLAGS, SEND_WRITE_ZEROES, CAN_MULTI_CONN
HandshakeFlags: FIXED_NEWSTYLE, NO_ZEROES
Size: 4294967296
Name: (null)
Port: 10809
Host: localhost
Providers:
1. Name: nbd0
   Mediasize: 4294967296 (4.0G)
   Sectorsize: 4096
   Mode: r0w0e0

```

Disconnect the device `nbd0`:

```
# gnbd disconnect nbd0
```

To connect to a named export:

```
# gnbd connect -n myexport nbdserver
nbd0
```

To connect to a non-standard port:

```
# gnbd connect -p 1234 nbdserver
nbd1
```

To connect using TLS and requiring a trusted certificate authority:

```
# gnbd connect -A cacert.pem -C cert.pem -K key.pem nbdserver
nbd2
```

To scale a device using TLS:

```
# gnbd scale -c 4 -A cacert.pem -C cert.pem -K key.pem nbd2
```

To test commands without installing outside of the source directory:

```
# make DEBUG_FLAGS="-g -O0 -DINVARIANTS -DWITNESS"
# cd mod
# make load
# cd ../lib
# GEOM_LIBRARY_PATH=. geom nbd connect nbdserver
nbd0
# GEOM_LIBRARY_PATH=. geom nbd disconnect nbd0
# cd ../mod
# make unload
```

## Manual

A manual page can be found in lib/gnbd.8, or installed as gnbd(8).
