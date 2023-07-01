# socks5-client

This is an educational project that implements part of the [`SOCKS 5` protocol].  It is inspired by the [`tor-resolve`] tool of the [Tor project], which passes any `DNS` request through the Tor network instead of onto the open Internet.

I wanted to write this to get some experience with [sockets programming in C], as well as use the Tor network to hide my `DNS` queries from The Man.

> Currently, the files `resolver.c` and `socks5-client-tor.c` are not being used.  They are intended for future development.

## Example

DNS resolution through Tor:

    socks5-client -p 9050 -h stackoverflow.com

This is analogous to:

    tor-resolve stackoverflow.com

## Debugging

You can use [`tcpdump`] to filter out all of the traffic except for `DNS` on your network adapter.  Of course, if sending the request through the Tor network, you shouldn't see any traffic related to your request going out through the network adapter (or on port 53):

```bash
$ sudo tcpdump -i wlp3s0 port 53
```

Instead, you'll need to watch the [`loopback`] interface on listen on port 9050, the default port for the Tor network daemon:

```bash
$ sudo tcpdump -i lo port 9050
```

## License

[GPLv3](COPYING)

## Author

Benjamin Toll

## References

- [`SOCKS 5` protocol]
- [`SOCKS 5` protocol on Wikipedia](https://en.wikipedia.org/wiki/SOCKS#SOCKS5)
- [Beej's Guide to Network Programming](https://beej.us/guide/bgnet/)
- [tor-resolve.c](https://github.com/torproject/tor/blob/main/src/tools/tor-resolve.c)

[`SOCKS 5` protocol]: https://datatracker.ietf.org/doc/html/rfc1928
[`tor-resolve`]: https://man.archlinux.org/man/tor-resolve.1.en
[Tor project]: https://www.torproject.org/
[sockets programming in C]: https://beej.us/guide/bgnet/html/split-wide/
[`tcpdump`]: https://www.man7.org/linux/man-pages/man1/tcpdump.1.html
[`loopback`]: /2019/09/23/on-loopback/

