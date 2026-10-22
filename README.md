# sni-scan

Find the best SNI for a VLESS + REALITY node, from the node itself. One file, no dependencies, Python 3.8+.

```sh
curl -fsSL https://raw.githubusercontent.com/getvlana/sni-scan/main/sni_scan.py | python3 - --near
```

```
looking for HTTPS sites next to 185.99.97.128 (its /24)…
  found 23: lexarthur.ru linksale.site …
testing 93 sites, 3 handshakes each…

  well-known sites
  sni                                       ms  ip
  www.autodesk.com                        21.4  2.23.245.217
  www.lg.com                              21.4  2.23.244.106
  www.asus.com                            21.5  18.172.112.57

  next to your server (same /24): the most natural fit, but open each one and make sure it is a real, harmless site
  www.lexarthur.ru                         0.9  185.99.97.65

  73 passed · 20 rejected (no TLS 1.3, no h2, bad cert, behind Cloudflare or unreachable)

  best: www.autodesk.com

  new node:
    curl -fsSL https://go.vlana.app/install.sh | sudo SNI=www.autodesk.com bash -s <TOKEN>
```

## Why the SNI matters

REALITY doesn't fake a certificate. It forwards the TLS handshake of a real site, so to anyone watching, your node *is* that site. That only holds up if the site behaves like what your server pretends to be:

| check | why |
|---|---|
| **TLS 1.3** | REALITY needs it |
| **HTTP/2 (h2)** | what a modern big site negotiates; a mismatch stands out |
| **valid certificate** for the name | the handshake is forwarded as is, so it has to be real |
| **not behind Cloudflare** | Cloudflare's IPs are everywhere; a "Cloudflare site" on a random VPS is a classic tell |
| **low latency** | the handshake time should fit a server near yours. A site 200 ms away answering in 20 ms from your IP looks wrong |

`--near` goes further: it looks at the other servers in your own /24 and offers the sites they host. Same network, same latency, nothing to explain. Open each one before using it: shared hosting ranges also host junk.

## Options

```
python3 sni_scan.py [domains…] [--near] [--tries 3] [--timeout 4] [--workers 24] [--top 10] [--json]
```

Pass your own domains to test only those. `--json` prints every result, passed and rejected with the reason, for scripts.

## License

AGPL-3.0, part of [Vlana](https://github.com/getvlana/vlana).
