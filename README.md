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

## Prerequisites

Building this project requires the FreeBSD base system and sources.  There are
no external dependencies.

The base system OpenSSL is used for TLS support.

## Building and Installing

To build and install for a production kernel:

```
# make
# make install
```

The Makefiles assume the FreeBSD source tree is placed at /usr/src but this can
be overridden:

```
# make SRCTOP=/path/to/my/freebsd
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

## Full TLS Example

Assuming FreeBSD sources are already installed in /usr/src, this example will
walk through the steps to set up a local NBD server and client for testing.

First, clone the repo:

```
# pkg install git
# git clone https://github.com/ryan-moeller/kernel-nbd-client.git
```

Now, we'll generate the TLS certificates:

```
# pkg install gnutls
# certtool --generate-privkey > cakey.pem
# cat > ca.info <<EOF
cn = testing nbd client
ca
cert_signing_key
EOF
# certtool \
    --generate-self-signed \
    --load-privkey cakey.pem \
    --template ca.info \
    --outfile cacert.pem
# certtool --generate-privkey > serverkey.pem
# cat > server.info <<EOF
organization = testing nbd client
cn = localhost
tls_www_server
encryption_key
signing_key
EOF
# certtool \
    --generate-certificate \
    --load-ca-certificate cacert.pem \
    --load-ca-privkey cakey.pem \
    --load-privkey serverkey.pem \
    --template server.info \
    --outfile servercert.pem
# certtool --generate-privkey > clientkey.pem
# cat > client.info <<EOF
country = US
state = Florida
locality = Orlando
organization = testing nbd client
cn = localhost
tls_www_client
encryption_key
signing_key
EOF
# certtool \
    --generate-certificate \
    --load-ca-certificate cacert.pem \
    --load-ca-privkey cakey.pem \
    --load-privkey clientkey.pem \
    --template client.info \
    --outfile clientcert.pem
```

Then, set up nbd-server.  The FreeBSD port is outdated and buggy, so we'll build
it ourselves.  More likely people will be connecting to an existing Linux
server, but to keep the example on one machine we must do a little patching.
At the time of writing the latest release is 3.26.1 and it has several bugs in
the server code which have been patched on the master branch, so we will clone
the repository from GitHub and checkout a known good commit, then patch a few
things so we can build only the nbd-server program on FreeBSD:

```
# pkg install autotools autoconf-archive pkgconf docbook2X glib
# git clone https://github.com/NetworkBlockDevice/nbd.git
# cd nbd
# git checkout 7a64238499823456bb83cdbfe6811f5db468b35b
# git apply ../kernel-nbd-client/nbd.patch
# ./autogen.sh
# ./configure
# make
# cd ..
# cat > nbdconfig <<EOF
[generic]
cacertfile = ${PWD}/cacert.pem
certfile = ${PWD}/servercert.pem
keyfile = ${PWD}/serverkey.pem
EOF
```

Now, we'll build the client code:

```
# cd kernel-nbd-client
# make
# make install
# cd ..
```

To minimize filesystem overhead for the backing file, mount a tmpfs and create
a sparse file for the server to export.  Then we can start the server:

```
# mkdir tmp
# mount -t tmpfs tmp ./tmp
# truncate -s 4g ./tmp/nbdfile
# ./nbd/nbd-server 10809 ./tmp/nbdfile -C ./nbdconfig
```

With the server running, we can connect the client and run some disk tests:

```
# gnbd load
# gnbd connect -c 4 \
    -A ${PWD}/cacert.pem \
    -C ${PWD}/clientcert.pem \
    -K ${PWD}/clientkey.pem \
    localhost
nbd0
# diskinfo -twic nbd0
```

The diskinfo command will run some tests and output the results.  For a more
intensive test, we can install fio:

```
# pkg install fio
# cat > nbd-test.fio <<EOF
# Based on ssd-test.fio
[global]
bs=4k
ioengine=posixaio
iodepth=8
direct=1
runtime=60
filename=/dev/nbd0

[seq-read]
rw=read
stonewall

[rand-read]
rw=randread
stonewall

[seq-write]
rw=write
stonewall

[rand-write]
rw=randwrite
stonewall
EOF
# fio ./nbd-test.fio
```

Finally, the cleanup:

```
# gnbd disconnect nbd0
# gnbd unload
# pkill nbd-server
# umount ./tmp
```
