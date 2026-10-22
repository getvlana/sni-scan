#!/usr/bin/env python3
"""Find the best SNI for a VLESS + REALITY node, from the node itself.

REALITY borrows the TLS handshake of a real site. The best one answers TLS 1.3 with HTTP/2,
has a valid certificate, isn't behind Cloudflare and sits close to your server, so a probe
sees a handshake that matches where your server actually is.

    python3 sni_scan.py                 test a list of well-known sites
    python3 sni_scan.py --near          also look for sites in your server's own /24
    python3 sni_scan.py --json          machine-readable output
    python3 sni_scan.py example.com ... test your own candidates

No dependencies. Python 3.8+.
"""
import argparse, concurrent.futures as cf, ipaddress, json, re, socket, ssl, statistics, sys, time, urllib.request

CANDIDATES = """
dl.google.com www.google.com www.youtube.com fonts.gstatic.com www.gstatic.com
www.microsoft.com learn.microsoft.com update.microsoft.com go.microsoft.com www.bing.com
www.apple.com swdist.apple.com itunes.apple.com gateway.icloud.com
www.amazon.com aws.amazon.com s3.amazonaws.com
www.mozilla.org addons.mozilla.org download-installer.cdn.mozilla.net
www.samsung.com www.nvidia.com www.amd.com www.intel.com www.dell.com www.hp.com www.lenovo.com
www.oracle.com www.ibm.com www.cisco.com www.vmware.com www.redhat.com
www.yahoo.com www.ebay.com www.paypal.com www.booking.com
www.spotify.com www.twitch.tv www.tiktok.com www.linkedin.com
github.com api.github.com objects.githubusercontent.com
www.wikipedia.org www.wikimedia.org upload.wikimedia.org
www.digitalocean.com www.hetzner.com www.ovh.com www.vultr.com www.linode.com
www.docker.com hub.docker.com registry-1.docker.io
www.debian.org deb.debian.org www.ubuntu.com archive.ubuntu.com
www.python.org pypi.org files.pythonhosted.org
www.nginx.com www.jetbrains.com code.visualstudio.com
www.speedtest.net www.adobe.com www.autodesk.com www.sony.com www.lg.com www.asus.com
""".split()

CF_FALLBACK = """173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18
190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14
172.64.0.0/13 131.0.72.0/22""".split()


def cloudflare_nets():
    try:
        with urllib.request.urlopen('https://www.cloudflare.com/ips-v4', timeout=5) as r:
            nets = r.read().decode().split()
    except Exception:
        nets = CF_FALLBACK
    return [ipaddress.ip_network(n) for n in nets]


def handshake(ip, sni, timeout):
    """One TLS handshake. Returns (ms, tls version, alpn, cert ok, cert names)."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(['h2', 'http/1.1'])
    if sni is None:  # neighbour discovery: we don't know the name yet, take whatever cert comes back
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    t = time.perf_counter()
    with socket.create_connection((ip, 443), timeout=timeout) as raw:
        tcp = (time.perf_counter() - t) * 1000
        try:
            with ctx.wrap_socket(raw, server_hostname=sni) as s:
                names = []
                if sni is None:
                    der = s.getpeercert(binary_form=True)
                    names = cert_names(der)
                return tcp, s.version(), s.selected_alpn_protocol(), True, names
        except ssl.SSLCertVerificationError:
            return tcp, None, None, False, []


def cert_names(der):
    """Hostnames in a DER certificate, without third-party parsers: scan for dNSName entries."""
    names, i = [], 0
    while True:
        i = der.find(b'\x82', i)  # [2] IMPLICIT IA5String = dNSName in subjectAltName
        if i < 0 or i + 2 > len(der):
            break
        n = der[i + 1]
        if n < 0x80 and i + 2 + n <= len(der):
            v = der[i + 2:i + 2 + n]
            if all(32 < b < 127 for b in v) and b'.' in v:
                names.append(v.decode())
        i += 1
    host = re.compile(r'^[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$')
    junk = ('.invalid', '.local', '.localhost', '.default', '.internal', '.test', '.example')
    return sorted({n for n in names if host.match(n) and not n.endswith(junk)}, key=len)


def test(sni, cf_nets, tries, timeout):
    r = {'sni': sni, 'ok': False}
    try:
        ip = socket.getaddrinfo(sni, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except Exception:
        r['why'] = 'no IPv4'
        return r
    r['ip'] = ip
    r['cloudflare'] = any(ipaddress.ip_address(ip) in n for n in cf_nets)
    rtts = []
    try:
        for _ in range(tries):
            ms, ver, alpn, cert, _ = handshake(ip, sni, timeout)
            rtts.append(ms)
    except Exception as e:
        r['why'] = type(e).__name__
        return r
    r.update(ms=round(statistics.median(rtts), 1), tls=ver, alpn=alpn, cert=cert)
    why = [w for w, bad in (('no TLS 1.3', ver != 'TLSv1.3'), ('no h2', alpn != 'h2'), ('bad cert', not cert), ('cloudflare', r['cloudflare'])) if bad]
    r['ok'] = not why
    if why:
        r['why'] = ', '.join(why)
    return r


def my_ip():
    for url in ('https://api.ipify.org', 'https://ifconfig.me/ip'):
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                return r.read().decode().strip()
        except Exception:
            pass
    return None


def neighbours(ip, timeout, workers):
    """Hosts in the same /24 that serve HTTPS, with the names on their certificates."""
    net = ipaddress.ip_network(ip + '/24', strict=False)
    found = set()

    def probe(h):
        try:
            _, ver, alpn, _, names = handshake(str(h), None, timeout)
            if ver == 'TLSv1.3' and alpn == 'h2':
                return names[:3]
        except Exception:
            pass
        return []

    with cf.ThreadPoolExecutor(workers) as ex:
        for names in ex.map(probe, [h for h in net.hosts() if str(h) != ip]):
            found.update(names)
    return sorted(found)


def main():
    ap = argparse.ArgumentParser(description='Find the best SNI for a VLESS + REALITY node.')
    ap.add_argument('domains', nargs='*', help='your own candidates (default: a built-in list of big sites)')
    ap.add_argument('--near', action='store_true', help="also discover sites in this server's /24")
    ap.add_argument('--tries', type=int, default=3, help='handshakes per site (median is kept)')
    ap.add_argument('--timeout', type=float, default=4)
    ap.add_argument('--workers', type=int, default=24)
    ap.add_argument('--top', type=int, default=10)
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args()

    tty = sys.stdout.isatty() and not a.json
    g = lambda s: f'\033[32m{s}\033[0m' if tty else s
    d = lambda s: f'\033[2m{s}\033[0m' if tty else s
    say = (lambda *x: print(*x, file=sys.stderr)) if a.json else print

    cands = list(dict.fromkeys(a.domains or CANDIDATES))
    near, mynet = [], None
    if a.near:
        ip = my_ip()
        if ip:
            mynet = ipaddress.ip_network(ip + '/24', strict=False)
            say(d(f'looking for HTTPS sites next to {ip} (its /24)…'))
            near = neighbours(ip, a.timeout, a.workers * 4)
            say(d(f'  found {len(near)}: {" ".join(near[:12])}{" …" if len(near) > 12 else ""}'))
            cands = near + cands
    cf_nets = cloudflare_nets()
    say(d(f'testing {len(cands)} sites, {a.tries} handshakes each…'))
    with cf.ThreadPoolExecutor(a.workers) as ex:
        res = list(ex.map(lambda s: test(s, cf_nets, a.tries, a.timeout), cands))
    for r in res:
        # a name from a neighbour's certificate only counts as near if it also resolves into our /24
        r['near'] = r['sni'] in near and 'ip' in r and ipaddress.ip_address(r['ip']) in mynet
    good = sorted((r for r in res if r['ok']), key=lambda r: r['ms'])
    bad = [r for r in res if not r['ok']]

    if a.json:
        print(json.dumps({'good': good, 'rejected': bad}, indent=1))
        return
    def table(title, rows):
        if not rows:
            return
        print(f'\n  {title}\n  {"sni":36} {"ms":>7}  ip')
        for r in rows[:a.top]:
            print(f'  {g(r["sni"].ljust(36))} {r["ms"]:>7}  {d(r["ip"])}')
    far = [r for r in good if not r['near']]
    close = [r for r in good if r['near']]
    table('well-known sites' if a.near else 'passed', far)
    if close:
        table('next to your server (same /24): the most natural fit, but open each one and make sure it is a real, harmless site', close)
    if not good:
        print('  nothing passed. try --near, or pass your own domains')
        sys.exit(1)
    print(d(f'\n  {len(good)} passed · {len(bad)} rejected (no TLS 1.3, no h2, bad cert, behind Cloudflare or unreachable)'))
    best = (far or close)[0]['sni']
    print(f'\n  best: {g(best)}\n')
    print(d('  new node:'))
    print(f'    curl -fsSL https://go.vlana.app/install.sh | sudo SNI={best} bash -s <TOKEN>')
    print(d('  docker:'))
    print(f'    docker run -d --network host -e TOKEN=<TOKEN> -e SNI={best} -v vlana:/etc/vlana ghcr.io/getvlana/node\n')


if __name__ == '__main__':
    main()
