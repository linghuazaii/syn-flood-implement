SYN FLOOD IMPLEMENT[Deprecated]
===================
## Note
This implementation won't cause SYN flood for \*nix systems. 

### Description
This is a simple example using `raw socket` to send `SYN` packet to remote server, and the intent is to consume **backlog of the listen queue** to cause remote server delying services on specified port theoretically.<br>
A problem is happened, which may stop me for some time to bring this theorem to practice. The problem is described below:<br>
<img src="https://github.com/linghuazaii/blog/blob/master/image/syn-flood/syn-packet.png"><br>
`client` send a `SYN` to `server`, and `server` responsed with correct `ACK Number`, I have read TCP RFC, the problem seems to be that, `kernel` didn't implement TCP RFC the strict way. You can track this question in [SO](http://stackoverflow.com/questions/40986978/create-half-open-tcp-connection-failed) for latest updates on this problem.<br>
<br>
**Update:**<br>
How foolish I am, I am using `raw socket`, so TCP state machine won't be started, and cause this `RST` is sent by `kernel`. This bug is fixed, `kernel` seems to have protection for `SYN FLOOD`, and `backlog` for every `socket descriptor` seems to increase dynamicly. But that's alright, every `half-open` connection will consume `kernel` resources, now imagin we have a `CLUSTER` to flood the target at the same time. HAHAHA...<br>
Wait! `kernel` seems to sustain a limit number of `half-open` connections, good job! `kernel`~<br>
<img src="https://github.com/linghuazaii/blog/blob/master/image/syn-flood/half-connection.png"><br>

## Usage
 - Just use `make` to do compiling.
 - Just use `make clean` to do cleaning.
 - Just use `./syn-flood --help` to print usage details.
 - And you must have `root` privilege to run this program.
 - What do I mean by `root` privilege? 1. Have `SUID` bit set by `root` 2. You have `sudo` privilege 3. You are already `root` and you are the GOD!
```
Usage: syn-flood [OPTION...] [-ehLnopPqQrStTvxXV?]

syn-flood version 1.0 by Charles, Liu.

 If you don't know exactly what these options mean, you can view Internet
Protocol(IP) RFC <https://tools.ietf.org/html/rfc791> and TCP RFC
<https://tools.ietf.org/html/rfc793>.
 Any questions, you can send email to me <charlesliu.cn.bj@gmail.com> or
<charlesliu.cn.bj@qq.com>.

  -e, --ethernet=ethernet    Specify the ethernet to send packet.
  -h, --host=host            Remote host(fqdn or ipv4 address) to start a SYN
                             FLOOD.
  -L, --list                 Get a list of STUN servers, if port is not given,
                             then it is default to 3478, some may not function
                             any more. You can Google more STUN server list,
                             don't depend on this one.
  -n, --packets=packets      Number of packets to send, default to 1.
  -o, --output=FILE          Output to FILE instead of standard output
  -p, --port=port            Remote port to start a SYN FLOOD.
  -P, --public-ip            This is used to get your public ipv4 adress, if
                             stun server is not set, dig will be used. If you
                             want to use STUN, `stun-server`,
                             `stun-server-port`, `stun-local-port` should be
                             specified befor `-P`.
  -q, -s, --quite, --silent  Don't produce any output
  -Q, --local-port=port      Specify local port to send SYN packat, default to
                             9765.
  -r, --resolve-dns          Resolve fqdn specified by host to ipv4 address.
  -S, --stun-server=server   STUN server fqdn or ipv4 address. This is used to
                             get your public ipv4 address.
  -t, --ttl=ttl              Time-To-Live of the IP packet, should be 1-255,
                             default value is 64.
  -T, --tos=precedence       Precedence of the IP packet, should be 0-7,
                             default value is 0.
  -v, --verbose              Produce verbose output and debug info
  -x, --stun-server-port=port   STUN server port, use UDP, default to 3478.
                             This is used to get your public ipv4 address.
  -X, --stun-local-port=port STUN local port, use UDP, default to 9764. This is
                             used to get your public ipv4 address.
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.

Report bugs to <charlesliu.cn.bj@gmail.com>.
```

## Copyright
 - This software if made by Charles, Liu, feel free to use and redistribute this code as you wish. And any illegal things caused by this software, consequences should be taken by the **attacker**.
 - Any bugs please mailto **charlesliu.cn.bj@gmail.com**
