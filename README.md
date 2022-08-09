# hmac-header

_See: [https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-http-mac-02](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-http-mac-02)_

This is an implementation of the IETF OAuth v2 HTTP MAC header from Draft 2.

## Differences from the Draft

### Naming

The draft refers to the key (`key`) and the key identifier (`id`), where the `key` is the shared secret that is never transmitted over the wire. The `id` is sent from the client to the server so the server can retrieve the known secret for the purposes of verifying the MAC.

In this repo, I've chosen to change this nomenclature to key and secret, in terms of key-value thinking.

### Hashing Algorithms

The draft mentions the strict use of either SHA1 or SHA256 as the hashing algorithm. I've opted to allow the implementer the freedom to choose their own algorithm.

Why?

Generally, SHA3-512 is my goto hashing algorithm of choice. It is my opinion that modern systems and scaling have progressed to the point where the stronger algorithm has become a good compromise between performance (e.g. SHA256) and strength (e.g. whirlpool). That said, the implementer will probably have different requirements, so they're free to use what they want.

**NOTE:** For the sake of best practices, it is **strongly recommended that you do not use MD5 or SHA1.** Really. Unless your risk is extremely low, **AND** you need to hash on a 68HC11 microcontroller, or something equally ancient and slow (modern μC's will perform SHA256 just fine), do not use the weaker hashes. At a bare minimum you should be using SHA256, and ideally SHA3-256 or better.

### Omitted `ext` Header Attribute

At this time, I chose to omit the `ext` header attribute. I'll add this in at a later time.
