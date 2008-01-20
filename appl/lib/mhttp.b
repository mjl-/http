implement Http;

include "sys.m";
include "bufio.m";
include "string.m";
include "filter.m";
include "encoding.m";
include "keyring.m";
include "security.m";
include "pkcs.m";
include "asn1.m";
include "sslsession.m";
include "ssl3.m";
include "mhttp.m";

sys: Sys;
bufio: Bufio;
str: String;
base64: Encoding;
inflate: Filter;
ssl3: SSL3;

Iobuf: import bufio;
Rq: import Filter;
Context: import ssl3;
prefix: import str;
sprint, fprint, print, FileIO: import sys;

methods := array[] of {"OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"};
versions := array[] of {"HTTP/1.0", "HTTP/1.1"};
bodymethods := array[] of {POST, PUT, DELETE, PROPFIND, MKCOL};
unsafemethods := array[] of {POST, PUT, DELETE, MKCOL, MOVE, PROPPATCH};

Eperm:	con "permission denied";

ssl_suites := array [] of {
        byte 0, byte 16r03,     # RSA_EXPORT_WITH_RC4_40_MD5
        byte 0, byte 16r04,     # RSA_WITH_RC4_128_MD5
        byte 0, byte 16r05,     # RSA_WITH_RC4_128_SHA
        byte 0, byte 16r06,     # RSA_EXPORT_WITH_RC2_CBC_40_MD5
        byte 0, byte 16r07,     # RSA_WITH_IDEA_CBC_SHA
        byte 0, byte 16r08,     # RSA_EXPORT_WITH_DES40_CBC_SHA
        byte 0, byte 16r09,     # RSA_WITH_DES_CBC_SHA
        byte 0, byte 16r0A,     # RSA_WITH_3DES_EDE_CBC_SHA

        byte 0, byte 16r0B,     # DH_DSS_EXPORT_WITH_DES40_CBC_SHA
        byte 0, byte 16r0C,     # DH_DSS_WITH_DES_CBC_SHA
        byte 0, byte 16r0D,     # DH_DSS_WITH_3DES_EDE_CBC_SHA
        byte 0, byte 16r0E,     # DH_RSA_EXPORT_WITH_DES40_CBC_SHA
        byte 0, byte 16r0F,     # DH_RSA_WITH_DES_CBC_SHA
        byte 0, byte 16r10,     # DH_RSA_WITH_3DES_EDE_CBC_SHA
        byte 0, byte 16r11,     # DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
        byte 0, byte 16r12,     # DHE_DSS_WITH_DES_CBC_SHA
        byte 0, byte 16r13,     # DHE_DSS_WITH_3DES_EDE_CBC_SHA
        byte 0, byte 16r14,     # DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
        byte 0, byte 16r15,     # DHE_RSA_WITH_DES_CBC_SHA
        byte 0, byte 16r16,     # DHE_RSA_WITH_3DES_EDE_CBC_SHA

        byte 0, byte 16r17,     # DH_anon_EXPORT_WITH_RC4_40_MD5
        byte 0, byte 16r18,     # DH_anon_WITH_RC4_128_MD5
        byte 0, byte 16r19,     # DH_anon_EXPORT_WITH_DES40_CBC_SHA
        byte 0, byte 16r1A,     # DH_anon_WITH_DES_CBC_SHA
        byte 0, byte 16r1B,     # DH_anon_WITH_3DES_EDE_CBC_SHA

        byte 0, byte 16r1C,     # FORTEZZA_KEA_WITH_NULL_SHA
        byte 0, byte 16r1D,     # FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA
        byte 0, byte 16r1E,     # FORTEZZA_KEA_WITH_RC4_128_SHA
};
ssl_comprs := array [] of {byte 0};


init(b: Bufio)
{
	sys = load Sys Sys->PATH;
	bufio = b;
	str = load String String->PATH;
	base64 = load Encoding Encoding->BASE64PATH;
	inflate = load Filter Filter->INFLATEPATH;
	inflate->init();
	ssl3 = load SSL3 SSL3->PATH;
	ssl3->init();
}

basicauth(user, pass: string): (string, string)
{
	return ("Authorization", "Basic "+string base64->enc(array of byte (user+":"+pass)));
}

isidempotent(method: int): int
{
	case method {
	GET or HEAD or PUT or DELETE or OPTIONS or TRACE or PROPFIND =>
		return 1;
	}
	return 0;
}

methodstr(method: int): string
{
	return methods[method];
}

versionstr(version: int): string
{
	return versions[version];
}

Url.unpack(s: string): (ref Url, string)
{
	scheme := "http";
	if(prefix("http://", s))
		s = s[len "http://":];
	else if(prefix("https://", s)) {
		s = s[len "https://":];
		scheme = "https";
	} else if(prefix("//", s))
		s = s[len "//":];
	usessl := scheme == "https";
	(addr, path) := str->splitl(s, "/");
	(host, port) := str->splitl(addr, ":");
	if(port == "" || port == ":") {
		port = "80";
		if(usessl)
			port = "443";
	} else
		port = port[1:];
	query: string;
	(path, query) = str->splitl(path, "?");
	if(path == "")
		path = "/";
	return (ref Url(usessl, scheme, host, port, decode(path), query), nil);
}

Url.pack(u: self ref Url): string
{
	s := "";
	if(u.host != nil) {
		s = u.scheme+"://"+u.host;
		if((!u.usessl && u.port != "80") || (u.usessl && u.port != "443"))
			s += ":"+u.port;
	}
	return s+u.packpath();
}

Url.packpath(u: self ref Url): string
{
	return encodepath(u.path)+u.query;
}

Url.addr(u: self ref Url): string
{
	if(u.host == nil)
		return nil;
	return sprint("net!%s!%s", u.host, u.port);
}

hex(c: int): int
{
	if(c >= '0' && c <= '9') return c-'0';
	if(c >= 'A' && c <= 'F')
		c += 'a'-'A';
	if(c >= 'a' && c <= 'f') return 10+c-'a';
	return -1;
}

decode(s: string): string
{
	sa := array of byte s;
	ra := array[len sa] of byte;
	si := 0;
	ri := 0;
	while(si < len sa) {
		c: byte;
		if(sa[si] == byte '%') {
			if(si+2 < len sa) {
				h1 := hex(int sa[si+1]);
				h2 := hex(int sa[si+2]);
				if(h1 < 0 || h2 < 0)
					return nil;
				c = byte ((h1 << 4) | h2);
				si += 3;
			} else
				return nil;
		} else if(sa[si] == byte '+') {
			c = byte ' ';
			si += 1;
		} else {
			c = sa[si];
			si += 1;
		}
		ra[ri++] = c;
	}
	return string ra[:ri];
}

reserved:	con ";/?:@&=+$,";
unreserved:	con "a-zA-Z0-9_.!~*'()-";
escaped:	con  "%0-9a-fA-F";
pchar:		con "/"+escaped+":@&=_$,"+unreserved;
uric:		con reserved+escaped+unreserved;

encodepath(s: string): string
{
	return _encode(s, pchar);
}

encodequery(s: string): string
{
	return _encode(s, uric);
}

_encode(s: string, okayspecial: string): string
{
	a := array of byte s;
	r := "";
	okay := "a-zA-Z0-9*_.-";
	for(i := 0; i < len a; i++) {
		c := int a[i];
		if(str->in(c, okay) || str->in(c, okayspecial))
			r += sprint("%c", c);
		#else if(c == ' ') r += "+";	not now, lighttpd webdav doesn't know it.  perhaps we it's illegal
		else
			r += sprint("%%%02X", c);
	}
	return r;
}

suffix(suf, s: string): int
{
	return len suf <= len s && suf == s[len s-len suf:];
}

strip(s, cl: string): string
{
	return droptl(str->drop(s, cl), cl);
}

droptl(s, pat: string): string
{
	while(s != nil && str->in(s[len s-1], pat))
		s = s[:len s-1];
	return s;
}

getline(b: ref Iobuf): (int, string)
{
	l := b.gets('\n');
	if(l == "")
		return (1, nil);
	if(suffix("\r\n", l))
		l = l[:len l-2];
	else if(suffix("\n", l))
		l = l[:len l-1];
	return (0, l);
}

hgetline(b: ref Iobuf): (int, string)
{
	(eof, l) := getline(b);
	if(!eof)
		say("<- "+droptl(l, "\r\n"));
	return (eof, l);
}

parseversion(s, line: string): (int, int, string)
{
	if(!str->prefix("HTTP/", s))
		return (0, 0, "bad http version line: "+line);
	s = s[len "HTTP/":];
	(majorstr, minorstr) := str->splitstrl(s, ".");
	if(minorstr == nil)
		return (0, 0, "bad http version line: "+line);
	minorstr = minorstr[1:];
	if(majorstr == "" || minorstr == "" || str->drop(majorstr, "0-9") != "" || str->drop(minorstr, "0-9") != "")
		return (0, 0, "bad http version: "+line);
	return (int majorstr, int minorstr, nil);
}

toversion(major, minor: int): int
{
	if(major == 1 && minor == 0)
		return HTTP_10;
	if(major == 1 && minor >= 1)
		return HTTP_11;
	raise sprint("unsupported http version: HTTP/%d.%d", major, minor);
}

fromversion(vers: int): (int, int)
{
	case vers {
	HTTP_10 =>	return (1, 0);
	HTTP_11 =>	return (1, 1);
	}
	raise "bad version value";
}

Hdrs.new(l: list of (string, string)): ref Hdrs
{
	return ref Hdrs(l);
}

Hdrs.read(b: ref Iobuf): (ref Hdrs, string)
{
	h := Hdrs.new(nil);
	for(;;) {
		(eof, l) := hgetline(b);
		if(eof)
			return (h, "eof from server while reading headers");
		if(l == "")
			break;
		if(l[0] == ' ' || l[0] == '\t') {
			if(h.l == nil)
				return (h, "first header claims to be continuation header, not possible");
			hh := hd h.l;
			hh = (hh.t0, strip(hh.t1+" "+l, " \t"));
			h.l = hh::tl h.l;
			say(sprint("Hdrs.read: continued, now: %q: %q", hh.t0, hh.t1));
			continue;
		}
		(k, v) := str->splitl(l, ":");
		if(v == nil)
			return (h, "bad header line: "+l);
		v = strip(v[1:], " \t");
		h.add(k, v);
		say(sprint("Hdrs.read: new: %q: %q", k, v));
	}
	return (h, nil);
}

Hdrs.set(h: self ref Hdrs, k, v: string)
{
	h.del(k, nil);
	h.add(k, v);
}

Hdrs.add(h: self ref Hdrs, k, v: string)
{
	h.l = (k, v)::h.l;
}

Hdrs.del(h: self ref Hdrs, k, v: string)
{
	k = str->tolower(k);
	v = str->tolower(v);
	r: list of (string, string);
	for(l := h.l; l != nil; l = tl l) {
		(lk, lv) := hd l;
		if(str->tolower(lk) != k || (v != nil && str->tolower(lv) != v))
			r = hd l::r;
	}
	h.l = r;
}

Hdrs.find(h: self ref Hdrs, k: string): (int, string)
{
say(sprint("Hdrs.find k=%q", k));
	l := h.findall(k);
	if(l == nil)
		return (0, nil);
say("have hdr");
	return (1, hd l);
}

Hdrs.findall(h: self ref Hdrs, k: string): list of string
{
	r: list of string;
	k = str->tolower(k);
	for(l := h.l; l != nil; l = tl l)
		if(str->tolower((hd l).t0) == k)
			r = (hd l).t1::r;
	return r;
}

Hdrs.get(h: self ref Hdrs, k: string): string
{
	return h.find(k).t1;
}

# get comma-separated list
Hdrs.getlist(h: self ref Hdrs, k: string): string
{
	s := "";
	for(l := h.findall(k); l != nil; l = tl l) {
		e := strip(hd l, " \t");
		if(e != nil)
			s += ", "+e;
	}
	if(s != nil)
		s = s[2:];
	return s;
}

Hdrs.has(h: self ref Hdrs, k, v: string): int
{
	k = str->tolower(k);
	v = str->tolower(v);
	for(l := h.l; l != nil; l = tl l)
		if(str->tolower((hd l).t0) == k && (v == nil || (hd l).t1 == v))
			return 1;
	return 0;
}

Hdrs.all(h: self ref Hdrs): list of (string, string)
{
	return h.l;
}


Req.mk(method: int, url: ref Url, version: int, h: ref Hdrs): ref Req
{
	(major, minor) := fromversion(version);
	return ref Req(method, url, major, minor, h, nil, nil);
}

Req.pack(r: self ref Req): string
{
	path := r.url.packpath();
	if(r.proxyaddr != nil)
		path = r.url.pack();
	q := sprint("%s %s HTTP/%d.%d\r\n", methods[r.method], path, r.major, r.minor);

	if(!r.h.has("Host", nil))
		q += sprint("Host: %s\r\n", r.url.host);
	if(r.body != nil && !r.h.has("Content-Length", nil))
		q += sprint("Content-Length: %d\r\n", len r.body);

	for(l := r.h.all(); l != nil; l = tl l)
		q += sprint("%s: %s\r\n", (hd l).t0, (hd l).t1);
	q += "\r\n";
	return q;
}

Req.write(r: self ref Req, fd: ref Sys->FD): string
{
	if(fprint(fd, "%s", r.pack()) < 0)
		return sprint("%r");
	say("request: "+r.pack());
	if(r.body != nil && len r.body > 0)
		if(sys->write(fd, r.body, len r.body) != len r.body)
			return sprint("%r");
	return nil;
}

Req.read(b: ref Iobuf): (ref Req, string)
{
	(eof, l) := hgetline(b);
	if(eof)
		return (nil, "eof reading request");

	meth, urlstr, vers: string;
	(meth, l) = str->splitstrl(l, " ");
	if(l == nil)
		return (nil, "bad request line");
	l = l[1:];
	(l, vers) = str->splitstrr(l, " ");
	if(l == nil)
		return (nil, "bad request line");
	l = l[:len l-1];
	urlstr = l;

	method := -1;
	for(i := 0; i < len methods && method == -1; i++)
		if(meth == methods[i])
			method = i;
	if(method == -1)
		return (nil, "unknown method");

	(major, minor, verr) := parseversion(vers, l);
	if(verr != nil)
		return (nil, verr);
	(u, err) := Url.unpack(urlstr);
	if(err != nil)
		return (nil, "bad url: "+err);
	(h, herr) := Hdrs.read(b);
	if(herr != nil)
		return (nil, "bad headers: "+herr);

	return (ref Req(method, u, major, minor, h, nil, nil), nil);
}

nfc := 0;
Req.dial(r: self ref Req): (ref Sys->FD, string)
{
	addr := r.url.addr();
	if(r.proxyaddr != nil)
		addr = r.proxyaddr;
	(ok, conn) := sys->dial(addr, nil);
	if(ok < 0)
		return (nil, sprint("dial %s: %r", addr));
	say("dial: dialed "+addr);
	if(r.url.usessl)
		return pushssl(conn.dfd, addr);
	return (conn.dfd, nil);
}

Req.version(r: self ref Req): int
{
	return toversion(r.major, r.minor);
}

status(r: ref Resp): string
{
	msg := "";
	case int r.st {
	101 =>	msg = "upgrade to: "+r.h.get("Upgrade");
	301 to 303 =>
		msg = "redirection to: "+r.h.get("Location");
	305 =>	msg = "use proxy: "+r.h.get("Location");
	401 =>	msg = "unauthorized for: "+r.h.get("WWW-Authenticate");
	405 =>	msg = "bad method, allowed are: "+r.h.get("Allow");
	407 =>	msg = "unauthorized for proxy: "+r.h.get("Proxy-Authenticate");
	416 =>	msg = "bad range requested, contents range: "+r.h.get("Content-Range");
	}
	if(msg != "")
		msg = ": "+msg;
	return sprint("%s (%s)%s", r.st, r.stmsg, msg);
}


Resp.mk(version: int, st, stmsg: string, h: ref Hdrs): ref Resp
{
	(major, minor) := fromversion(version);
	return ref Resp(major, minor, st, stmsg, h);
}

Resp.pack(r: self ref Resp): string
{
	q := sprint("HTTP/%d.%d %s %s\r\n", r.major, r.minor, r.st, r.stmsg);
	for(l := r.h.all(); l != nil; l = tl l)
		q += sprint("%s: %s\r\n", (hd l).t0, (hd l).t1);
	q += "\r\n";
	return q;
}

Resp.write(r: self ref Resp, fd: ref Sys->FD): string
{
	if(fprint(fd, "%s", r.pack()) < 0)
		return sprint("%r");
	return nil;
}

Resp.read(b: ref Iobuf): (ref Resp, string)
{
	(eof, l) := hgetline(b);
	if(eof)
		return (nil, "eof reading http response line");

	(s, rem) := str->splitl(l, " ");
	(major, minor, verr) := parseversion(s, l);
	if(verr != nil)
		return (nil, verr);
	if(rem == nil)
		return (nil, "missing response code: "+l);
	(st, stmsg) := str->splitl(rem[1:], " ");
	if(len st != 3 || str->take(st, "0-9") != st)
		return (nil, "bad response status: "+l);
	if(stmsg != nil)
		stmsg = stmsg[1:];

	(h, err) := Hdrs.read(b);
	if(err != nil)
		return (nil, err);
	return (ref Resp(major, minor, st, stmsg, h), nil);
}

Resp.hasbody(r: self ref Resp, reqmethod: int): int
{
	case int r.st {
	100 or 101 or 204 or 205 or 304 => return 0;
	}
	return reqmethod != HEAD;
}

Resp.body(r: self ref Resp, b: ref Iobuf): (ref Sys->FD, string)
{
	fd: ref Sys->FD;
	err: string;
	if(str->tolower(r.h.find("Transfer-Encoding").t1) == "chunked")
		(fd, err) = pushchunked(b);
	else if(((have, v) := r.h.find("Content-Length")).t0)
		(fd, err) = pushlength(b, int v);
	else
		(fd, err) = pusheof(b);
	if(err != nil)
		return (nil, err);

	(have, v) = r.h.find("Content-Encoding");
	if(have)
		case str->tolower(v) {
		"gzip" =>	(fd, err) = pushinflate(fd, 1);
		"deflate" =>	(fd, err) = pushinflate(fd, 0);
		* =>		return (nil, "unknown content-encoding: "+v);
		}
	if(err != nil)
		return (nil, err);
	return (fd, nil);
}

Resp.version(r: self ref Resp): int
{
	return toversion(r.major, r.minor);
}

pushchunked(b: ref Iobuf): (ref Sys->FD, string)
{
	f := sprint("fcn%d.%d", sys->pctl(0, nil), nfc++);
	fio := sys->file2chan("#shttp", f);
	spawn fcchunked(fio, b);
	fd := sys->open(sprint("#shttp/%s", f), Sys->OREAD);
	if(fd == nil)
		return (nil, sprint("opening chunked file: %r"));
	return (fd, nil);
}

fcchunked(fio: ref FileIO, b: ref Iobuf)
{
	firstc := 1;
	clen := 0;
	eof := 0;
	for(;;) alt {
	(nil, count, nil, rc) := <-fio.read =>
		if(rc == nil)
			return;
		
		if(clen == 0 && !eof) {
			(end, l) := getline(b);
			if(end) {
				rc <-= (nil, "eof while reading chunk length");
				return;
			}
			if(!firstc && l == "") {
				(end, l) = getline(b);
				if(end) {
					rc <-= (nil, "eof while reading chunk length");
					return;
				}
			}
			(l, nil) = str->splitl(l, ";");
			l = strip(l, " \t");
			#say("new chunk: "+l);
			if(l != "0") {
				rem: string;
				(clen, rem) = str->toint(l, 16);
				if(l == "" || rem != nil) {
					rc <-= (nil, "bad chunk length: "+l);
					return;
				}
				#say(sprint("clen now %d", clen));
				firstc = 0;
			} else {
				eof = 1;
				(end, l) = getline(b);
			}
		}
		if(eof) {
			rc <-= (array[0] of byte, nil);
			continue;
		}

		want := count;
		if(want > clen)
			want = clen;
		have := b.read(d := array[want] of byte, len d);
		if(have < 0) {
			rc <-= (nil, sprint("%r"));
			return;
		} else if(have == 0) {
			rc <-= (nil, "premature eof");
			return;
		} else
			rc <-= (d[:have], nil);
		clen -= have;

	(nil, nil, nil, wc) := <-fio.write =>
		if(wc == nil)
			return;
		wc <-= (-1, Eperm);
	}
}

pushlength(b: ref Iobuf, n: int): (ref Sys->FD, string)
{
	f := sprint("fcn%d.%d", sys->pctl(0, nil), nfc++);
	fio := sys->file2chan("#shttp", f);
	spawn fclength(fio, b, n);
	fd := sys->open(sprint("#shttp/%s", f), Sys->OREAD);
	if(fd == nil)
		return (nil, sprint("opening fixed-length file: %r"));
	return (fd, nil);
}

fclength(fio: ref FileIO, b: ref Iobuf, n: int)
{
	for(;;) alt {
	(nil, count, nil, rc) := <-fio.read =>
		if(rc == nil)
			return;
		if(n == 0) {
			rc <-= (array[0] of byte, nil);
			continue;
		}
		want := count;
		if(want > n)
			want = n;
		have := b.read(d := array[want] of byte, len d);
		if(have < 0) {
			rc <-= (nil, sprint("%r"));
			return;
		} else if(have == 0) {
			rc <-= (nil, "premature eof");
			return;
		} else
			rc <-= (d[:have], nil);
		n -= have;
		say(sprint("fclength: n=%d", n));

	(nil, nil, nil, wc) := <-fio.write =>
		if(wc == nil)
			return;
		wc <-= (-1, Eperm);
	}
}

pusheof(b: ref Iobuf): (ref Sys->FD, string)
{
	say("PUSHEOF");
	f := sprint("fcn%d.%d", sys->pctl(0, nil), nfc++);
	fio := sys->file2chan("#shttp", f);
	spawn fceof(fio, b);
	fd := sys->open(sprint("#shttp/%s", f), Sys->OREAD);
	if(fd == nil)
		return (nil, sprint("opening eof file: %r"));
	return (fd, nil);
}

fceof(fio: ref FileIO, b: ref Iobuf)
{
	eof := 0;
	for(;;) alt {
	(nil, count, nil, rc) := <-fio.read =>
		if(rc == nil)
			return;
		if(eof) {
			rc <-= (array[0] of byte, nil);
			continue;
		}
		n := b.read(d := array[count] of byte, count);
		if(n < 0) {
			rc <-= (nil, sprint("%r"));
			return;
		} else
			rc <-= (d[:n], nil);
		if(n == 0)
			eof = 1;

	(nil, nil, nil, wc) := <-fio.write =>
		if(wc == nil)
			return;
		wc <-= (-1, Eperm);
	}
}

pushinflate(fd: ref Sys->FD, gzip: int): (ref Sys->FD, string)
{
	say("PUSHINFLATE");
	f := sprint("fcn%d.%d", sys->pctl(0, nil), nfc++);
	fio := sys->file2chan("#shttp", f);
	spawn fcinflate(fio, fd, gzip);
	nfd := sys->open(sprint("#shttp/%s", f), Sys->OREAD);
	if(nfd == nil)
		return (nil, sprint("opening inflate file: %r"));
	return (nfd, nil);
}

fcinflate(fio: ref FileIO, fd: ref Sys->FD, gzip: int)
{
	pid: int;
	flags := "";
	if(gzip == 1)
		flags += "h";
	mc := inflate->start(flags);
	pick m := <- mc {
	Start =>	pid = m.pid;
	* =>		return say("invalid start message from inflate filter");
	}

	buf := array[0] of byte;

	for(;;) alt {
	(nil, count, nil, rc) := <-fio.read =>
		if(rc == nil) {
			kill(pid);
			return;
		}
		if(pid >= 0 && len buf == 0) {
			pick m := <- mc {
			Fill =>
				say(sprint("read,inflate: fill len=%d", len m.buf));
				if((m.reply <-= sys->read(fd, m.buf, len m.buf)) < 0) {
					rc <-= (nil, sprint("%r"));
					return;
				}
			Result =>
				say(sprint("read,inflate: result len=%d", len m.buf));
				buf = array[len m.buf] of byte;
				buf[:] = m.buf;
				m.reply <-= 0;
			Finished =>
				say(sprint("read,inflate: finished leftover-len=%d", len m.buf));
			Info =>
				say("inflate: "+m.msg);
			Error =>
				rc <-= (nil, sprint("inflate: %s", m.e));
				return;
			* =>
				rc <-= (nil, "inflate: unexpected response from filter");
				kill(pid);
				return;
			}
		}

		take := count;
		if(take > len buf)
			take = len buf;
		rc <-= (buf[:take], nil);
		buf = buf[take:];

	(nil, nil, nil, wc) := <-fio.write =>
		if(wc == nil) {
			kill(pid);
			return;
		}
		wc <-= (-1, Eperm);
	}
}


pushssl(origfd: ref Sys->FD, addr: string): (ref Sys->FD, string)
{
	say("PUSHSSL");
	sslx := Context.new();
	info := ref SSL3->Authinfo(ssl_suites, ssl_comprs, nil, 0, nil, nil, nil);
	(err, vers) :=  sslx.client(origfd, addr, 3, info);
	if(err != nil)
		return (nil, err);
	say(sprint("ssl connected version=%d", vers));

	f := sprint("fcn%d.%d", sys->pctl(0, nil), nfc++);
	fio := sys->file2chan("#shttp", f);
	spawn fcssl(fio, sslx);
	fd := sys->open(sprint("#shttp/%s", f), Sys->ORDWR);
	if(fd == nil)
		return (nil, sprint("opening ssl file: %r"));
	return (fd, nil);
}

fcssl(fio: ref FileIO, sslx: ref Context)
{
	#say("fcssl: new");
	eof := 0;
	for(;;) alt {
	(nil, count, nil, rc) := <-fio.read =>
		#say(sprint("fcssl: have read, count=%d", count));
		if(rc == nil) {
			#say("sslfc: rc == nil");
			return;
		}
		if(eof) {
			#say(sprint("sslfc: eof reading"));
			rc <-= (array[0] of byte, nil);
			continue;
		}
		n := sslx.read(d := array[count] of byte, len d);
		if(n < 0) {
			#say(sprint("sslfc: error: %r"));
			rc <-= (nil, sprint("%r"));
			return;
		}else {
			#say(sprint("sslfc: returning %d bytes", n));
			rc <-= (d[:n], nil);
		}
		if(n == 0)
			eof = 1;

	(nil, d, nil, wc) := <-fio.write =>
		if(wc == nil) {
			#say("fcssl: wc == nil");
			return;
		}
		if(sslx.write(d, len d) != len d) {
			wc <-= (-1, sprint("%r"));
			#say("fcssl: error writing");
			return;
		} else {
			wc <-= (len d, nil);
			#say("fcssl: written");
		}
	}
}

kill(pid: int)
{
	fd := sys->open(sprint("/prog/%d/ctl", pid), Sys->OWRITE);
	if(fd != nil)
		fprint(fd, "kill");
}

say(s: string)
{
	if(debug)
		sys->fprint(sys->fildes(2), "%s\n", s);
}
