[![progress-banner](https://backend.codecrafters.io/progress/dns-server/c72abb05-fd2e-4532-a03a-ac5990daf4a2)](https://app.codecrafters.io/users/codecrafters-bot?r=2qF)

This is a starting point for C++ solutions to the
["Build Your Own DNS server" Challenge](https://app.codecrafters.io/courses/dns-server/overview).

In this challenge, you'll build a DNS server that's capable of parsing and
creating DNS packets, responding to DNS queries, handling various record types
and doing recursive resolve. Along the way we'll learn about the DNS protocol,
DNS packet format, root servers, authoritative servers, forwarding servers,
various record types (A, AAAA, CNAME, etc) and more.

**Note**: If you're viewing this repo on GitHub, head over to
[codecrafters.io](https://codecrafters.io) to try the challenge.

# Passing the first stage

The entry point for your `your_program.sh` implementation is in
`src/server.cpp`. Study and uncomment the relevant code, and push your changes
to pass the first stage:

```sh
git add .
git commit -m "pass 1st stage" # any msg
git push origin master
```

Time to move on to the next stage!

# Stage 2 & beyond

Note: This section is for stages 2 and beyond.

1. Ensure you have `cmake` installed locally
1. Run `./your_program.sh` to run your program, which is implemented in
   `src/server.cpp`.
1. Commit your changes and run `git push origin master` to submit your solution
   to CodeCrafters. Test output will be streamed to your terminal.

# Notes

* The DNS messages are built on top of UDP packets.

* Sending just a UDP packet:
   * `echo -n "hello" > /dev/udp/127.0.0.1/2053`
   * [One has to use `127.0.0.1` instead of `localhost`](https://stackoverflow.com/questions/9696129/how-to-send-only-one-udp-packet-with-netcat#comment54050586_16568803)

* Sending DNS request messages:
   * `dig @127.0.0.1 -p 2053 +noedns codecrafters.io`
      * Displays response header fields
      * Results in 2 DNS packets
      * Both have the same header

      or
   * `nslookup -port=2053 codecrafters.io 127.0.0.1`
      * Results in 4 DNS packets
      * The first and third packets are shown by the server
      * 1 and 2 have the same header and 3 and 4 have the same header