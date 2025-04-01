# FreeBSD GEOM NBD Client

[![14.2-RELEASE Build Status](https://api.cirrus-ci.com/github/ryan-moeller/kernel-nbd-client.svg?branch=main&task=releases/amd64/14.2-RELEASE)](https://cirrus-ci.com/github/ryan-moeller/kernel-nbd-client)
[![15.0-CURRENT Build Status](https://api.cirrus-ci.com/github/ryan-moeller/kernel-nbd-client.svg?branch=main&task=snapshots/amd64/15.0-CURRENT)](https://cirrus-ci.com/github/ryan-moeller/kernel-nbd-client)

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
* Zero copies are performed for writes where possible.  Reads need some work.

## Prerequisites

Building this project requires the FreeBSD base system and sources.  There are
no external dependencies.

The base system OpenSSL is used for TLS support.

For TLS connections, ktls(4) must be enabled:

```
# sysctl kern.ipc.tls.enable=1
kern.ipc.tls.enable: 0 -> 1
```

ktls(4) is enabled by default on 15.0-CURRENT.

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

To build for a debug kernel with WITNESS and INVARIANTS:

```
# make DEBUG_FLAGS="-g -O0 -DWITNESS -DINVARIANTS"
# make DEBUG_FLAGS="-g -O0 -DWITNESS -DINVARIANTS" install
```

Note: you can check which of WITNESS and INVARIANTS need to be defined for the
running kernel:

```
# sysctl kern.conftxt | egrep '(WITNESS|INVARIANTS)$'
options WITNESS
options INVARIANTS
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

First, clone the repo and build the client:

```
# pkg install git
# git clone https://github.com/ryan-moeller/kernel-nbd-client.git
# cd kernel-nbd-client
# make
# make install
# cd -
```

Now, we'll generate the TLS certificates:

```
# pkg install gnutls
# certtool --generate-privkey > ca-key.pem
# cat > ca.info <<EOF
cn = testing nbd client
ca
cert_signing_key
EOF
# certtool \
    --generate-self-signed \
    --load-privkey ca-key.pem \
    --template ca.info \
    --outfile ca-cert.pem
# certtool --generate-privkey > server-key.pem
# cat > server.info <<EOF
organization = testing nbd client
cn = localhost
tls_www_server
encryption_key
signing_key
EOF
# certtool \
    --generate-certificate \
    --load-ca-certificate ca-cert.pem \
    --load-ca-privkey ca-key.pem \
    --load-privkey server-key.pem \
    --template server.info \
    --outfile server-cert.pem
# certtool --generate-privkey > client-key.pem
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
    --load-ca-certificate ca-cert.pem \
    --load-ca-privkey ca-key.pem \
    --load-privkey client-key.pem \
    --template client.info \
    --outfile client-cert.pem
```

Then, set up the server.  The FreeBSD nbd-server port is outdated and buggy,
so we'll use nbdkit.  We'll start the server with a 4 GiB memory disk:

```
# pkg install nbdkit
# nbdkit --tls-certificates ${PWD} memory 4G
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
# pkill nbdkit
```

## Debugging

As a starting point for debugging the kernel module, an lldb lua script is
included.  It will collect and print information about the connections in the
kernel module.  To run the script interactively, first attach lldb to the
kernel:

```
# lldb -c /dev/mem /boot/kernel/kernel
(lldb) target create "/boot/kernel/kernel" --core "/dev/mem"
Core file '/dev/mem' (x86_64) was loaded.
(lldb)
```

Then at the (lldb) prompt:

```
(lldb) script dofile 'kernel-nbd-client/gnbd.lua'
(g_nbd_softc) *nc_softc = {
  sc_host = 0xfffff8033c562130 "localhost"
  sc_port = 0xfffff80003848e00 "10809"
  sc_name = 0xfffff8000369a520 ""
  sc_description = 0x0000000000000000
  sc_size = 4294967296
   = {
    sc_flags = 21037059
     = (sc_handshake_flags = 3, sc_transmission_flags = 321)
  }
  sc_minblocksize = 512
  sc_prefblocksize = 4096
  sc_maxpayload = 262144
  sc_unit = 0
  sc_tls = true
  sc_provider = 0xfffff803bc6b1800
  sc_queue = {
    tqh_first = NULL
    tqh_last = 0xfffff803bbbca448
  }
  sc_queue_mtx = {
    lock_object = (lo_name = "gnbd:queue", lo_flags = 16973824, lo_data = 0, lo_witness = 0xfffff8085eb89a80)
    mtx_lock = 0
  }
  sc_connections = {
    slh_first = 0xfffff80003550e00
  }
  sc_nconns = 2
  sc_conns_mtx = {
    lock_object = (lo_name = "gnbd:connections", lo_flags = 16973824, lo_data = 0, lo_witness = 0xfffff8085eb89b00)
    mtx_lock = 0
  }
  sc_flush_lock = {
    lock_object = (lo_name = "gnbd:flush", lo_flags = 36896768, lo_data = 0, lo_witness = 0xfffff8085eb89b80)
    sx_lock = 1
  }
}
(nbd_conn *) 0xfffff8000b046400
(nbd_conn_state) nc_state = NBD_CONN_CONNECTED  (uint64_t) nc_seq = 1
thread #15: tid = 114432, 0xffffffff80b89ce0 kernel`sched_switch(td=0xfffff8029fc44740, flags=259) at sched_ule.c:2290:26, name = '(pid 35826) gnbd/gnbd nbd0 sender'
frame #5: 0xffffffff830486a6 geom_nbd.ko`nbd_conn_sender(arg=0xfffff8000b046400) at g_nbd.c:899:4
thread #16: tid = 114815, 0xffffffff80b89ce0 kernel`sched_switch(td=0xfffff806a9b24740, flags=259) at sched_ule.c:2290:26, name = '(pid 35826) gnbd/gnbd nbd0 receiver'
frame #9: 0xffffffff830489d9 geom_nbd.ko`nbd_conn_receiver(arg=0xfffff8000b046400) at g_nbd.c:976:3
socket[
  options<KEEPALIVE>, state<ISCONNECTED>, error<0>, rerror<0>,
  snd<flags<AUTOSIZE>,state<0>,acc<0>,ccc<0>,hiwat<1572864>,lowat<2048>>,
  rcv<flags<TLS_RX,TLS_RX_RESYNC,AUTOSIZE,WAIT>,state<0>,acc<0>,ccc<0>,hiwat<1572864>,lowat<16>>
]
(nbd_inflight) *tqh_first = {
  ni_bio = 0xfffff805cf00c900
  ni_cookie = 0
  ni_refs = 1
  ni_inflight = {
    tqe_next = NULL
    tqe_prev = 0xfffff8000b046420
  }
}
bio[READ<0>4294963200:4096]
(nbd_conn *) 0xfffff80003550e00
(nbd_conn_state) nc_state = NBD_CONN_CONNECTED  (uint64_t) nc_seq = 0
thread #17: tid = 114816, 0xffffffff80b89ce0 kernel`sched_switch(td=0xfffff8028d4ff000, flags=259) at sched_ule.c:2290:26, name = '(pid 35826) gnbd/gnbd nbd0 sender'
frame #5: 0xffffffff830486a6 geom_nbd.ko`nbd_conn_sender(arg=0xfffff80003550e00) at g_nbd.c:899:4
thread #18: tid = 114817, 0xffffffff80b89ce0 kernel`sched_switch(td=0xfffff8029fc40740, flags=259) at sched_ule.c:2290:26, name = '(pid 35826) gnbd/gnbd nbd0 receiver'
frame #9: 0xffffffff830489d9 geom_nbd.ko`nbd_conn_receiver(arg=0xfffff80003550e00) at g_nbd.c:976:3
socket[
  options<KEEPALIVE>, state<ISCONNECTED>, error<0>, rerror<0>,
  snd<flags<AUTOSIZE>,state<0>,acc<0>,ccc<0>,hiwat<1572864>,lowat<2048>>,
  rcv<flags<TLS_RX,TLS_RX_RESYNC,AUTOSIZE,WAIT>,state<0>,acc<0>,ccc<0>,hiwat<1572864>,lowat<16>>
]
(lldb)
```

Note: the kernel module must be built with debug symbols by setting DEBUG_FLAGS
in the invocation of `make` for the lldb script to work.  Then when loaded by
`make load` from the mod/ directory without being installed, the symbols will be
automatically found by lldb.  Otherwise when installing, DEBUG_FLAGS must also
be set in the invocation of `make install` for debug symbols to be installed.

## Performance Metrics

Profiles are collected for a selection of synthetic workloads as part of the CI
testing.  Each trace is of fio running with the [ci.fio](ci.fio) job file and
iodepth and bs from the table below on an NBD device with 4 connections.

The latest results can be found below:

| FreeBSD Version | TLS | IO Depth | Blocksize | Fio JSON+  | Collapsed Stacks | Flame Graph | Speedscope |
| --------------- | --- | -------- | --------- | ---------- | ---------------- | ----------- | ---------- |
| 14.2-RELEASE    | no  | 32       | 4k        | [json][1a] | [txt][1b]        | [svg][1c]   | [🔬][1d]   |
| 14.2-RELEASE    | no  | 4        | 1m        | [json][2a] | [txt][2b]        | [svg][2c]   | [🔬][2d]   |
| 14.2-RELEASE    | yes | 32       | 4k        | [json][3a] | [txt][3b]        | [svg][3c]   | [🔬][3d]   |
| 14.2-RELEASE    | yes | 4        | 1m        | [json][4a] | [txt][4b]        | [svg][4c]   | [🔬][4d]   |
| 15.0-CURRENT    | no  | 32       | 4k        | [json][5a] | [txt][5b]        | [svg][5c]   | [🔬][5d]   |
| 15.0-CURRENT    | no  | 4        | 1m        | [json][6a] | [txt][6b]        | [svg][6c]   | [🔬][6d]   |
| 15.0-CURRENT    | yes | 32       | 4k        | [json][7a] | [txt][7b]        | [svg][7c]   | [🔬][7d]   |
| 15.0-CURRENT    | yes | 4        | 1m        | [json][8a] | [txt][8b]        | [svg][8c]   | [🔬][8d]   |

[1a]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F14.2-RELEASE/fio/traces/notls-32-4k.fio.json?branch=stats
[1b]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F14.2-RELEASE/trace/traces/notls-32-4k.collapsedstack.txt?branch=stats
[1c]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F14.2-RELEASE/svg/traces/notls-32-4k.svg?branch=stats
[1d]: https://speedscope.app#profileURL=https%3A%2F%2Fapi.cirrus-ci.com%2Fv1%2Fartifact%2Fgithub%2Fryan-moeller%2Fkernel-nbd-client%2Freleases%252Famd64%252F14.2-RELEASE%2Ftrace%2Ftraces%2Fnotls-32-4k.collapsedstack.txt%3Fbranch%3Dstats&title=FreeBSD%2014.2-RELEASE%20notls-32-4k

[2a]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F14.2-RELEASE/fio/traces/notls-4-1m.fio.json?branch=stats
[2b]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F14.2-RELEASE/trace/traces/notls-4-1m.collapsedstack.txt?branch=stats
[2c]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F14.2-RELEASE/svg/traces/notls-4-1m.svg?branch=stats
[2d]: https://speedscope.app#profileURL=https%3A%2F%2Fapi.cirrus-ci.com%2Fv1%2Fartifact%2Fgithub%2Fryan-moeller%2Fkernel-nbd-client%2Freleases%252Famd64%252F14.2-RELEASE%2Ftrace%2Ftraces%2Fnotls-4-1m.collapsedstack.txt%3Fbranch%3Dstats&title=FreeBSD%2014.2-RELEASE%20notls-4-1m

[3a]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F14.2-RELEASE/fio/traces/tls-32-4k.fio.json?branch=stats
[3b]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F14.2-RELEASE/trace/traces/tls-32-4k.collapsedstack.txt?branch=stats
[3c]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F14.2-RELEASE/svg/traces/tls-32-4k.svg?branch=stats
[3d]: https://speedscope.app#profileURL=https%3A%2F%2Fapi.cirrus-ci.com%2Fv1%2Fartifact%2Fgithub%2Fryan-moeller%2Fkernel-nbd-client%2Freleases%252Famd64%252F14.2-RELEASE%2Ftrace%2Ftraces%2Ftls-32-4k.collapsedstack.txt%3Fbranch%3Dstats&title=FreeBSD%2014.2-RELEASE%20tls-32-4k

[4a]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F14.2-RELEASE/fio/traces/tls-4-1m.fio.json?branch=stats
[4b]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F14.2-RELEASE/trace/traces/tls-4-1m.collapsedstack.txt?branch=stats
[4c]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F14.2-RELEASE/svg/traces/tls-4-1m.svg?branch=stats
[4d]: https://speedscope.app#profileURL=https%3A%2F%2Fapi.cirrus-ci.com%2Fv1%2Fartifact%2Fgithub%2Fryan-moeller%2Fkernel-nbd-client%2Freleases%252Famd64%252F14.2-RELEASE%2Ftrace%2Ftraces%2Ftls-4-1m.collapsedstack.txt%3Fbranch%3Dstats&title=FreeBSD%2014.2-RELEASE%20tls-4-1m

[5a]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/snapshots%2Famd64%2F15.0-CURRENT/fio/traces/notls-32-4k.fio.json?branch=stats
[5b]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/snapshots%2Famd64%2F15.0-CURRENT/trace/traces/notls-32-4k.collapsedstack.txt?branch=stats
[5c]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/snapshots%2Famd64%2F15.0-CURRENT/svg/traces/notls-32-4k.svg?branch=stats
[5d]: https://speedscope.app#profileURL=https%3A%2F%2Fapi.cirrus-ci.com%2Fv1%2Fartifact%2Fgithub%2Fryan-moeller%2Fkernel-nbd-client%2Fsnapshots%252Famd64%252F15.0-CURRENT%2Ftrace%2Ftraces%2Fnotls-32-4k.collapsedstack.txt%3Fbranch%3Dstats&title=FreeBSD%2015.0-CURRENT%20notls-32-4k

[6a]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/snapshots%2Famd64%2F15.0-CURRENT/fio/traces/notls-4-1m.fio.json?branch=stats
[6b]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/snapshots%2Famd64%2F15.0-CURRENT/trace/traces/notls-4-1m.collapsedstack.txt?branch=stats
[6c]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/snapshots%2Famd64%2F15.0-CURRENT/svg/traces/notls-4-1m.svg?branch=stats
[6d]: https://speedscope.app#profileURL=https%3A%2F%2Fapi.cirrus-ci.com%2Fv1%2Fartifact%2Fgithub%2Fryan-moeller%2Fkernel-nbd-client%2Fsnapshots%252Famd64%252F15.0-CURRENT%2Ftrace%2Ftraces%2Fnotls-4-1m.collapsedstack.txt%3Fbranch%3Dstats&title=FreeBSD%2015.0-CURRENT%20notls-4-1m

[7a]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/snapshots%2Famd64%2F15.0-CURRENT/fio/traces/tls-32-4k.fio.json?branch=stats
[7b]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/snapshots%2Famd64%2F15.0-CURRENT/trace/traces/tls-32-4k.collapsedstack.txt?branch=stats
[7c]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/snapshots%2Famd64%2F15.0-CURRENT/svg/traces/tls-32-4k.svg?branch=stats
[7d]: https://speedscope.app#profileURL=https%3A%2F%2Fapi.cirrus-ci.com%2Fv1%2Fartifact%2Fgithub%2Fryan-moeller%2Fkernel-nbd-client%2Fsnapshots%252Famd64%252F15.0-CURRENT%2Ftrace%2Ftraces%2Ftls-32-4k.collapsedstack.txt%3Fbranch%3Dstats&title=FreeBSD%2015.0-CURRENT%20tls-32-4k

[8a]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/snapshots%2Famd64%2F15.0-CURRENT/fio/traces/tls-4-1m.fio.json?branch=stats
[8b]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/snapshots%2Famd64%2F15.0-CURRENT/trace/traces/tls-4-1m.collapsedstack.txt?branch=stats
[8c]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/snapshots%2Famd64%2F15.0-CURRENT/svg/traces/tls-4-1m.svg?branch=stats
[8d]: https://speedscope.app#profileURL=https%3A%2F%2Fapi.cirrus-ci.com%2Fv1%2Fartifact%2Fgithub%2Fryan-moeller%2Fkernel-nbd-client%2Fsnapshots%252Famd64%252F15.0-CURRENT%2Ftrace%2Ftraces%2Ftls-4-1m.collapsedstack.txt%3Fbranch%3Dstats&title=FreeBSD%2015.0-CURRENT%20tls-4-1m
