# FreeBSD GEOM NBD Client

[![14.3-RELEASE Build Status](https://api.cirrus-ci.com/github/ryan-moeller/kernel-nbd-client.svg?branch=main&task=releases/amd64/14.3-RELEASE)](https://cirrus-ci.com/github/ryan-moeller/kernel-nbd-client)
[![15.0-ALPHA1 Build Status](https://api.cirrus-ci.com/github/ryan-moeller/kernel-nbd-client.svg?branch=main&task=releases/amd64/15.0-ALPHA1)](https://cirrus-ci.com/github/ryan-moeller/kernel-nbd-client)

This is a Network Block Device (NBD) client for the FreeBSD kernel GEOM
framework.

The project consists of a kernel driver for the NBD GEOM class in mod/ and a
user library for the geom(8) control utility in lib/.

## Features

This client supports the following noteworthy features:

* Established connections are handed off to the kernel, allowing reroot onto the
  network-backed devices.
* Supports using multiple connections to the NBD server to parallelize commands.
* Supports structured replies with an option to force simple replies.
* Supports optional TLS encryption using ktls(4).
* Zero copies are performed for writes where possible.  Work is needed to
  support cxgbe(4) TCP-offload module DDP for zero-copy reads.

## Prerequisites

Building this project requires the FreeBSD base system and sources.  There are
no external dependencies.

The base system OpenSSL is used for TLS support.

For TLS connections, ktls(4) must be enabled:

```
# sysctl kern.ipc.tls.enable=1
kern.ipc.tls.enable: 0 -> 1
```

ktls(4) is enabled by default on 15.0-ALPHA1.

Only architectures with a direct map of physical memory are supported at this
time.  This currently includes amd64, arm64, and (usually) powerpc64.

## Building and Installing

Build and install for a production kernel:

```
# make
# make install
```

The Makefiles assume the FreeBSD source tree is placed at /usr/src but this can
be overridden:

```
# make SRCTOP=/path/to/my/freebsd
```

Build for a debug kernel with WITNESS and INVARIANTS:

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

List exports of an NBD server:

```
# gnbd exports nbdserver
myexport    optional description
```

```
# gnbd exports -p 1234 nbdserver
[default export]
```

Connect to a named export:

```
# gnbd connect -n myexport nbdserver
nbd0
```

Connect to a non-standard port:

```
# gnbd connect -p 1234 nbdserver
nbd1
```

Connect using TLS and requiring a trusted certificate authority:

```
# gnbd connect -A cacert.pem -C cert.pem -K key.pem nbdserver
nbd2
```
Connect using a UNIX-domain socket:

```
# gnbd connect /path/to/server.socket
nbd3
```

Scale a device using TLS:

```
# gnbd scale -c 4 -A cacert.pem -C cert.pem -K key.pem nbd2
```

Mount an NBD-backed root filesystem from an export matching the hostname:

```
# gnbd connect -c 2 -n $(hostname) nbdserver
nbd0
# gpart show nbd0
=>      40  20971440  nbd0  GPT  (10G)
        40        24        - free -  (12K)
        64  20971392     1  freebsd-ufs  (10G)
  20971456        24        - free -  (12K)
# kenv vfs.root.mountfrom=ufs:/dev/nbd0p1
# reboot -r
```

Automatically reconnect failed connections (edit for TLS):

```
# cp devd.conf.sample /etc/devd/nbd.conf
# service devd restart
```

Test commands without installing outside of the source directory:

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
# fio kernel-nbd-client/ci.fio --iodepth=8 --bsrange=512-1m --filename=/dev/nbd0
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
  sc_host = 0xfffff80003613090 "localhost"
  sc_port = 0xfffff80003613080 "10809"
  sc_name = 0xfffff80003613070 "mbp"
  sc_description = 0x0000000000000000
  sc_size = 549755813888
   = {
    sc_flags = 158138371
     = (sc_handshake_flags = 3, sc_transmission_flags = 2413)
  }
  sc_minblocksize = 512
  sc_prefblocksize = 16384
  sc_maxpayload = 1048576
  sc_unit = 0
  sc_tls = false
  sc_geom = 0xfffff8003d1af100
  sc_provider = 0xfffff80003344000
  sc_queue = {
    tqh_first = NULL
    tqh_last = 0xfffff80003347150
  }
  sc_queue_mtx = {
    lock_object = (lo_name = "gnbd:queue", lo_flags = 16973824, lo_data = 0, lo_witness = 0xfffff8085eb8b700)
    mtx_lock = 0
  }
  sc_connections = {
    slh_first = 0xfffff80003e5b000
  }
  sc_nconns = 2
  sc_nactive = 2
  sc_conns_mtx = {
    lock_object = (lo_name = "gnbd:connections", lo_flags = 16973824, lo_data = 0, lo_witness = 0xfffff8085eb8b780)
    mtx_lock = 0
  }
  sc_flushing = false
  sc_flush_lock = {
    lock_object = (lo_name = "gnbd:flush", lo_flags = 36896768, lo_data = 0, lo_witness = 0xfffff8085eb8b800)
    sx_lock = 1
  }
}
(nbd_conn *) 0xfffff80003d8ca00
(nbd_conn_state) nc_state = NBD_CONN_CONNECTED  (uint64_t) nc_seq = 2624849
thread #31: tid = 101027, 0xffffffff80ba81f2 kernel`sched_switch(td=0xfffff8006876a780, flags=259) at sched_ule.c:2448:26, name = '(pid 6052) gnbd/gnbd nbd0 sender'
frame #5: 0xffffffff834b2a4b geom_nbd.ko`nbd_conn_sender(arg=0xfffff80003d8ca00) at g_nbd.c:1188:4
Full Backtrace:
frame #0: 0xffffffff80ba81f2 kernel`sched_switch(td=0xfffff8006876a780, flags=259) at sched_ule.c:2448:26
frame #1: 0xffffffff80b82462 kernel`mi_switch(flags=259) at kern_synch.c:530:2
frame #2: 0xffffffff80bd80c9 kernel`sleepq_switch(wchan=0xfffff80003347150, pri=<unavailable>) at subr_sleepqueue.c:608:2
frame #3: 0xffffffff80bd7f9c kernel`sleepq_wait(wchan=<unavailable>, pri=<unavailable>) at subr_sleepqueue.c:659:2 [artificial]
frame #4: 0xffffffff80b819e5 kernel`_sleep(ident=0xfffff80003347150, lock=0xfffff80003347160, priority=555, wmesg="gnbd:queue", sbt=0, pr=0, flags=256) at kern_synch.c:221:3
frame #5: 0xffffffff834b2a4b geom_nbd.ko`nbd_conn_sender(arg=0xfffff80003d8ca00) at g_nbd.c:1188:4
frame #6: 0xffffffff80b25ca2 kernel`fork_exit(callout=(geom_nbd.ko`nbd_conn_sender at g_nbd.c:1163), arg=0xfffff80003d8ca00, frame=0xfffffe013d57ff40) at kern_fork.c:1153:2
frame #7: 0xffffffff810950de kernel`fork_trampoline at exception.S:1065
thread #32: tid = 101121, 0xffffffff80ba81f2 kernel`sched_switch(td=0xfffff802a0a50780, flags=259) at sched_ule.c:2448:26, name = '(pid 6052) gnbd/gnbd nbd0 receiver'
frame #7: 0xffffffff834b2c8e geom_nbd.ko`nbd_conn_receiver(arg=0xfffff80003d8ca00) at g_nbd.c:1259:3
Full Backtrace:
frame #0: 0xffffffff80ba81f2 kernel`sched_switch(td=0xfffff802a0a50780, flags=259) at sched_ule.c:2448:26
frame #1: 0xffffffff80b82462 kernel`mi_switch(flags=259) at kern_synch.c:530:2
frame #2: 0xffffffff80bd80c9 kernel`sleepq_switch(wchan=0xfffff80003d8ca60, pri=<unavailable>) at subr_sleepqueue.c:608:2
frame #3: 0xffffffff80bd7f9c kernel`sleepq_wait(wchan=<unavailable>, pri=<unavailable>) at subr_sleepqueue.c:659:2 [artificial]
frame #4: 0xffffffff80af9b00 kernel`_cv_wait(cvp=0xfffff80003d8ca60, lock=0xfffff8006f6001e0) at kern_condvar.c:153:2
frame #5: 0xffffffff834b5c0e geom_nbd.ko`nbd_conn_recv_mbufs(nc=0xfffff80003d8ca00, len=16, mp=0xfffffe013d4dae90) at g_nbd.c:806:4
frame #6: 0xffffffff834b5511 geom_nbd.ko`nbd_conn_recv(nc=0xfffff80003d8ca00) at g_nbd.c:864:10
frame #7: 0xffffffff834b2c8e geom_nbd.ko`nbd_conn_receiver(arg=0xfffff80003d8ca00) at g_nbd.c:1259:3
frame #8: 0xffffffff80b25ca2 kernel`fork_exit(callout=(geom_nbd.ko`nbd_conn_receiver at g_nbd.c:1246), arg=0xfffff80003d8ca00, frame=0xfffffe013d4daf40) at kern_fork.c:1153:2
frame #9: 0xffffffff810950de kernel`fork_trampoline at exception.S:1065
socket[
  options<KEEPALIVE>, state<ISCONNECTED>, error<0>, rerror<0>,
  snd<flags<AUTOSIZE,UPCALL>,state<0>,acc<0>,ccc<0>,hiwat<1572864>,lowat<1572865>>,
  rcv<flags<UPCALL>,state<0>,acc<0>,ccc<0>,hiwat<1572864>,lowat<16>>
]
(inflight bio) cookie=2624848 refs=1 bio[READ<UNMAPPED>137438953472:512]
(nbd_conn *) 0xfffff80003e5b000
(nbd_conn_state) nc_state = NBD_CONN_CONNECTED  (uint64_t) nc_seq = 160134
thread #33: tid = 101122, 0xffffffff80ba81f2 kernel`sched_switch(td=0xfffff802a0a53780, flags=259) at sched_ule.c:2448:26, name = '(pid 6052) gnbd/gnbd nbd0 sender'
frame #5: 0xffffffff834b2a4b geom_nbd.ko`nbd_conn_sender(arg=0xfffff80003e5b000) at g_nbd.c:1188:4
Full Backtrace:
frame #0: 0xffffffff80ba81f2 kernel`sched_switch(td=0xfffff802a0a53780, flags=259) at sched_ule.c:2448:26
frame #1: 0xffffffff80b82462 kernel`mi_switch(flags=259) at kern_synch.c:530:2
frame #2: 0xffffffff80bd80c9 kernel`sleepq_switch(wchan=0xfffff80003347150, pri=<unavailable>) at subr_sleepqueue.c:608:2
frame #3: 0xffffffff80bd7f9c kernel`sleepq_wait(wchan=<unavailable>, pri=<unavailable>) at subr_sleepqueue.c:659:2 [artificial]
frame #4: 0xffffffff80b819e5 kernel`_sleep(ident=0xfffff80003347150, lock=0xfffff80003347160, priority=555, wmesg="gnbd:queue", sbt=0, pr=0, flags=256) at kern_synch.c:221:3
frame #5: 0xffffffff834b2a4b geom_nbd.ko`nbd_conn_sender(arg=0xfffff80003e5b000) at g_nbd.c:1188:4
frame #6: 0xffffffff80b25ca2 kernel`fork_exit(callout=(geom_nbd.ko`nbd_conn_sender at g_nbd.c:1163), arg=0xfffff80003e5b000, frame=0xfffffe013d610f40) at kern_fork.c:1153:2
frame #7: 0xffffffff810950de kernel`fork_trampoline at exception.S:1065
thread #34: tid = 101123, 0xffffffff80ba81f2 kernel`sched_switch(td=0xfffff80266920000, flags=259) at sched_ule.c:2448:26, name = '(pid 6052) gnbd/gnbd nbd0 receiver'
frame #7: 0xffffffff834b2c8e geom_nbd.ko`nbd_conn_receiver(arg=0xfffff80003e5b000) at g_nbd.c:1259:3
Full Backtrace:
frame #0: 0xffffffff80ba81f2 kernel`sched_switch(td=0xfffff80266920000, flags=259) at sched_ule.c:2448:26
frame #1: 0xffffffff80b82462 kernel`mi_switch(flags=259) at kern_synch.c:530:2
frame #2: 0xffffffff80bd80c9 kernel`sleepq_switch(wchan=0xfffff80003e5b060, pri=<unavailable>) at subr_sleepqueue.c:608:2
frame #3: 0xffffffff80bd7f9c kernel`sleepq_wait(wchan=<unavailable>, pri=<unavailable>) at subr_sleepqueue.c:659:2 [artificial]
frame #4: 0xffffffff80af9b00 kernel`_cv_wait(cvp=0xfffff80003e5b060, lock=0xfffff8006f6085e0) at kern_condvar.c:153:2
frame #5: 0xffffffff834b5c0e geom_nbd.ko`nbd_conn_recv_mbufs(nc=0xfffff80003e5b000, len=16, mp=0xfffffe013d642e90) at g_nbd.c:806:4
frame #6: 0xffffffff834b5511 geom_nbd.ko`nbd_conn_recv(nc=0xfffff80003e5b000) at g_nbd.c:864:10
frame #7: 0xffffffff834b2c8e geom_nbd.ko`nbd_conn_receiver(arg=0xfffff80003e5b000) at g_nbd.c:1259:3
frame #8: 0xffffffff80b25ca2 kernel`fork_exit(callout=(geom_nbd.ko`nbd_conn_receiver at g_nbd.c:1246), arg=0xfffff80003e5b000, frame=0xfffffe013d642f40) at kern_fork.c:1153:2
frame #9: 0xffffffff810950de kernel`fork_trampoline at exception.S:1065
socket[
  options<KEEPALIVE>, state<ISCONNECTED>, error<0>, rerror<0>,
  snd<flags<AUTOSIZE,UPCALL>,state<0>,acc<0>,ccc<0>,hiwat<1572864>,lowat<1572865>>,
  rcv<flags<UPCALL>,state<0>,acc<0>,ccc<0>,hiwat<1572864>,lowat<16>>
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
| 14.3-RELEASE    | no  | 32       | 4k        | [json][1a] | [txt][1b]        | [svg][1c]   | [🔬][1d]   |
| 14.3-RELEASE    | no  | 4        | 1m        | [json][2a] | [txt][2b]        | [svg][2c]   | [🔬][2d]   |
| 14.3-RELEASE    | yes | 32       | 4k        | [json][3a] | [txt][3b]        | [svg][3c]   | [🔬][3d]   |
| 14.3-RELEASE    | yes | 4        | 1m        | [json][4a] | [txt][4b]        | [svg][4c]   | [🔬][4d]   |
| 15.0-ALPHA1     | no  | 32       | 4k        | [json][5a] | [txt][5b]        | [svg][5c]   | [🔬][5d]   |
| 15.0-ALPHA1     | no  | 4        | 1m        | [json][6a] | [txt][6b]        | [svg][6c]   | [🔬][6d]   |
| 15.0-ALPHA1     | yes | 32       | 4k        | [json][7a] | [txt][7b]        | [svg][7c]   | [🔬][7d]   |
| 15.0-ALPHA1     | yes | 4        | 1m        | [json][8a] | [txt][8b]        | [svg][8c]   | [🔬][8d]   |

[1a]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F14.3-RELEASE/fio/traces/notls-32-4k.fio.json
[1b]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F14.3-RELEASE/trace/traces/notls-32-4k.collapsedstack.txt
[1c]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F14.3-RELEASE/svg/traces/notls-32-4k.svg
[1d]: https://speedscope.app#profileURL=https%3A%2F%2Fapi.cirrus-ci.com%2Fv1%2Fartifact%2Fgithub%2Fryan-moeller%2Fkernel-nbd-client%2Freleases%252Famd64%252F14.3-RELEASE%2Ftrace%2Ftraces%2Fnotls-32-4k.collapsedstack.txt&title=FreeBSD%2014.3-RELEASE%20notls-32-4k

[2a]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F14.3-RELEASE/fio/traces/notls-4-1m.fio.json
[2b]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F14.3-RELEASE/trace/traces/notls-4-1m.collapsedstack.txt
[2c]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F14.3-RELEASE/svg/traces/notls-4-1m.svg
[2d]: https://speedscope.app#profileURL=https%3A%2F%2Fapi.cirrus-ci.com%2Fv1%2Fartifact%2Fgithub%2Fryan-moeller%2Fkernel-nbd-client%2Freleases%252Famd64%252F14.3-RELEASE%2Ftrace%2Ftraces%2Fnotls-4-1m.collapsedstack.txt&title=FreeBSD%2014.3-RELEASE%20notls-4-1m

[3a]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F14.3-RELEASE/fio/traces/tls-32-4k.fio.json
[3b]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F14.3-RELEASE/trace/traces/tls-32-4k.collapsedstack.txt
[3c]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F14.3-RELEASE/svg/traces/tls-32-4k.svg
[3d]: https://speedscope.app#profileURL=https%3A%2F%2Fapi.cirrus-ci.com%2Fv1%2Fartifact%2Fgithub%2Fryan-moeller%2Fkernel-nbd-client%2Freleases%252Famd64%252F14.3-RELEASE%2Ftrace%2Ftraces%2Ftls-32-4k.collapsedstack.txt&title=FreeBSD%2014.3-RELEASE%20tls-32-4k

[4a]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F14.3-RELEASE/fio/traces/tls-4-1m.fio.json
[4b]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F14.3-RELEASE/trace/traces/tls-4-1m.collapsedstack.txt
[4c]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F14.3-RELEASE/svg/traces/tls-4-1m.svg
[4d]: https://speedscope.app#profileURL=https%3A%2F%2Fapi.cirrus-ci.com%2Fv1%2Fartifact%2Fgithub%2Fryan-moeller%2Fkernel-nbd-client%2Freleases%252Famd64%252F14.3-RELEASE%2Ftrace%2Ftraces%2Ftls-4-1m.collapsedstack.txt&title=FreeBSD%2014.3-RELEASE%20tls-4-1m

[5a]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F15.0-ALPHA1/fio/traces/notls-32-4k.fio.json
[5b]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F15.0-ALPHA1/trace/traces/notls-32-4k.collapsedstack.txt
[5c]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F15.0-ALPHA1/svg/traces/notls-32-4k.svg
[5d]: https://speedscope.app#profileURL=https%3A%2F%2Fapi.cirrus-ci.com%2Fv1%2Fartifact%2Fgithub%2Fryan-moeller%2Fkernel-nbd-client%2Freleases%252Famd64%252F15.0-ALPHA1%2Ftrace%2Ftraces%2Fnotls-32-4k.collapsedstack.txt&title=FreeBSD%2015.0-ALPHA1%20notls-32-4k

[6a]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F15.0-ALPHA1/fio/traces/notls-4-1m.fio.json
[6b]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F15.0-ALPHA1/trace/traces/notls-4-1m.collapsedstack.txt
[6c]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F15.0-ALPHA1/svg/traces/notls-4-1m.svg
[6d]: https://speedscope.app#profileURL=https%3A%2F%2Fapi.cirrus-ci.com%2Fv1%2Fartifact%2Fgithub%2Fryan-moeller%2Fkernel-nbd-client%2Freleases%252Famd64%252F15.0-ALPHA1%2Ftrace%2Ftraces%2Fnotls-4-1m.collapsedstack.txt&title=FreeBSD%2015.0-ALPHA1%20notls-4-1m

[7a]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F15.0-ALPHA1/fio/traces/tls-32-4k.fio.json
[7b]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F15.0-ALPHA1/trace/traces/tls-32-4k.collapsedstack.txt
[7c]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F15.0-ALPHA1/svg/traces/tls-32-4k.svg
[7d]: https://speedscope.app#profileURL=https%3A%2F%2Fapi.cirrus-ci.com%2Fv1%2Fartifact%2Fgithub%2Fryan-moeller%2Fkernel-nbd-client%2Freleases%252Famd64%252F15.0-ALPHA1%2Ftrace%2Ftraces%2Ftls-32-4k.collapsedstack.txt&title=FreeBSD%2015.0-ALPHA1%20tls-32-4k

[8a]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F15.0-ALPHA1/fio/traces/tls-4-1m.fio.json
[8b]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F15.0-ALPHA1/trace/traces/tls-4-1m.collapsedstack.txt
[8c]: https://api.cirrus-ci.com/v1/artifact/github/ryan-moeller/kernel-nbd-client/releases%2Famd64%2F15.0-ALPHA1/svg/traces/tls-4-1m.svg
[8d]: https://speedscope.app#profileURL=https%3A%2F%2Fapi.cirrus-ci.com%2Fv1%2Fartifact%2Fgithub%2Fryan-moeller%2Fkernel-nbd-client%2Freleases%252Famd64%252F15.0-ALPHA1%2Ftrace%2Ftraces%2Ftls-4-1m.collapsedstack.txt&title=FreeBSD%2015.0-ALPHA1%20tls-4-1m
