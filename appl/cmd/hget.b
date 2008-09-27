implement Hget;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "draw.m";
include "arg.m";
include "string.m";
	str: String;
include "bufio.m";
	bufio: Bufio;
	Iobuf: import bufio;
include "mhttp.m";
	http: Http;
	Url, Hdrs, Req, Resp: import http;


Hget: module {
	init:	fn(nil: ref Draw->Context, nil: list of string);
};


hversion: int;
Pflag := cflag := dflag := fflag := pflag := vflag := qflag := 0;
outfile: string;
postbody: array of byte;
hdrs: list of (string, string);
proxyaddr: string;
method := Http->GET;

bout: ref Iobuf;


init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	str = load String String->PATH;
	arg := load Arg Arg->PATH;
	bufio = load Bufio Bufio->PATH;
	http = load Http Http->PATH;
	if(http == nil)
		fail(sprint("loading http, %q: %r", Http->PATH));
	http->init(bufio);

	hversion = Http->HTTP_11;
	arg->init(args);
	arg->setusage(arg->progname()+" [-cdfpqv] [-m method] [-P body] [-H version] [-h header value] [-o file] [-x proxyaddr] url");
	while((c := arg->opt()) != 0)
		case c {
		'H' =>	case arg->earg() {
			"1.0" =>  hversion = Http->HTTP_10;
			"1.1" =>  hversion = Http->HTTP_11;
			* =>	warn("invalid http version");
				arg->usage();
			}
		'P' =>	Pflag = 1;
			postbody = array of byte arg->earg();
		'c' =>	cflag = 1;
		'd' =>	dflag = 1;
		'f' =>	fflag = 1;
		'h' =>	k := arg->earg();
			v := arg->earg();
			hdrs = (k, v)::hdrs;
		'm' =>	m := arg->earg();
			case str->tolower(m) {
			"trace" =>	method = Http->TRACE;
			"head"	=>	method = Http->HEAD;
			"get"	=>	method = Http->GET;
			"post"	=>	method = Http->POST;
			* =>		warn("bad method");
					arg->usage();
			}
		'p' =>	pflag = 1;
		'o' =>	outfile = arg->earg();
		'q' =>	qflag = 1;
		'v' =>	vflag = 1;
		'x' =>	proxyaddr = arg->earg();
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args != 1) {
		warn("url missing");
		arg->usage();
	}
	urlstr := hd args;

	if(pflag && Pflag) {
		warn("-p and -P incompatible");
		arg->usage();
	}
	if(method != Http->POST && (pflag || Pflag)) {
		warn("pflag or Pflag only compatible with POST");
		arg->usage();
	}
	if(qflag && vflag) {
		warn("-q and -v incompatible");
		arg->usage();
	}
	if(cflag && outfile == nil) {
		warn("-c needs -o");
		arg->usage();
	}

	http->debug = dflag;

	(url, err) := Url.unpack(urlstr);
	if(err != nil)
		fail("parsing url: "+err);

	if(pflag)
		postbody = readbody();

	if(pflag || Pflag)
		method = Http->POST;
	if(fflag)
		hdrs = ("Cache-Control", "no-cache")::hdrs;

	if(outfile != nil) {
		if(cflag)
			bout = bufio->open(outfile, bufio->OWRITE);
		else
			bout = bufio->create(outfile, bufio->OWRITE, 8r666);
		if(bout == nil)
			fail(sprint("opening %s: %r", outfile));
	} else {
		bout = bufio->fopen(sys->fildes(1), bufio->OWRITE);
		if(bout == nil)
			fail(sprint("fopen stdout: %r"));
	}
	off := big 0;
	if(cflag) {
		bout.seek(big 0, bufio->SEEKEND);
		off = bout.offset();
		say(sprint("local file %bd bytes", off));
		hdrs = ("Range", sprint("bytes=%bd-", off))::hdrs;
	}

	req := Req.mk(method, url, hversion, Hdrs.new(hdrs));

	req.body = postbody;
	req.proxyaddr = proxyaddr;
	#if(nflag)
	#	req.redir = 0;
	#if(Rflag)
	#	req.referer = 1;

	sys->pctl(sys->NEWPGRP, nil);

	fd: ref Sys->FD;
	(fd, err) = req.dial();
	if(err == nil)
		err = req.write(fd);
	if(err != nil)
		fail(err);

	b := bufio->fopen(fd, Bufio->OREAD);
	if(b == nil)
		fail(sprint("bufio open: %r"));
	resp: ref Resp;
	(resp, err) = Resp.read(b);
	if(err != nil)
		fail(err);

	mlength := big -1;
	(have, lenstr) := resp.h.find("content-length");
	if(have)
		mlength = big lenstr;
	if(req.h.has("range", nil)) {
		(range, v) := resp.h.find("content-range");
		(rfirst, rlast, rlength, hdrerr) := parserange(v);
		if(range && hdrerr != nil)
			fail("bad content-range header: "+hdrerr);
		case resp.st {
		"206" =>
			say(sprint("have 206, rfirst %bd rlast %bd rlength %q", rfirst, rlast, rlength));
			if(rfirst != off)
				fail("partial content does not start at requested offset");
			if(rlength != "*" && rlast != big -1 && rlast+big 1 != big rlength)
				fail("partial content does not reach to end of file, as requested");
			if(rlength != "*")
				mlength = big rlength;
			else
				mlength -= off;
		"416" =>
			if(rlength != "*" && big rlength == off) {
				if(!qflag)
					warn("already have entire file");
				return;
			}
			fail("server could not fulfil partial request");
		* =>
			fail("expected partial response (status=206), received status="+resp.st);
		}
	}
	if(resp.st[0] != '2')
		fail(sprint("request unsuccesful: %s (%s)", resp.st, resp.stmsg));

	if(!resp.hasbody(method)) {
		if(!qflag)
			warn("result has no body");
		return;
	}

	rfd: ref Sys->FD;
	(rfd, err) = resp.body(b);
	if(err != nil)
		fail(err);

	respch := chan of (array of byte, string);
	waitch := chan of int;
	tickch := chan of int;
	spawn reader(rfd, respch, waitch);

	say(sprint("mlength %bd", mlength));
	nsteps := big 20;
	step := big 1;
	tickpid := -1;
	if(!qflag && mlength < big 0) {
		spawn ticker(tickch, pidch := chan of int);
		tickpid = <- pidch;
	} else {
		step = mlength / big nsteps;
		if(step < big 1)
			step = big 1; # prevent division by zero
	}

	prev := new := off;
	havesteps := off / step;
	for(i := big 0; !qflag && tickpid < 0 && i < havesteps; i++)
		sys->fprint(sys->fildes(2), ".");

loop:
	for(;;) {
		alt {
		(buf, errmsg) := <- respch =>
			if(errmsg != nil)
				fail(errmsg);
			if(buf == nil)
				break loop;
			if(bout.write(buf, len buf) != len buf)
				fail(sprint("writing: %r"));
			waitch <-= 0;
			new += big len buf;
			if(!qflag && tickpid < 0) {
				while(havesteps < new / step) {
					sys->fprint(sys->fildes(2), ".");
					havesteps++;
				}
			}
		<- tickch =>
			if(prev != new)
				sys->fprint(sys->fildes(2), ".");
			prev = new;
		}
	}
	if(tickpid >= 0)
		kill(tickpid);
	if(!qflag && mlength >= big 0) {
		while(havesteps++ < nsteps)
			sys->fprint(sys->fildes(2), ".");
	}
	if(!qflag)
		sys->fprint(sys->fildes(2), "\n");
	bout.close();
}

parserange(s: string): (big, big, string, string)
{
	origs := s;
	if(!str->prefix("bytes ", s))
		return (big 0, big 0, nil, "missing \"bytes\": "+origs);
	s = s[len "bytes ":];

	(range, clen) := str->splitstrl(s, "/");
	if(clen != nil)
		clen = clen[1:];
	if(range == nil || clen == nil)
		return (big 0, big 0, nil, "missing range or length: "+origs);
	clen = strip(clen);
	range = strip(range);
	(f, l) := str->splitstrl(range, "-");
	first := last := big -1;
	f = strip(f);
	if(f != nil)
		first = big f;
	if(l != nil)
		l = strip(l[1:]);
	if(l != nil)
		last = big l;
	if(clen != "*" && (last >= big clen || big clen < big 0) || first >= big 0 && last >= big 0 && last < first)
		return (big 0, big 0, nil, "message length < 0, or last past message length, or last < first: "+origs);
	if(first == big -1 && last == big -1)
		return (big 0, big 0, nil, "missing first or last of range: "+origs);
	return (first, last, clen, nil);
}

strip(s: string): string
{
	s = str->drop(s, " \t");
	while(s != nil && str->in(s[len s - 1], " \t"))
		s = s[:len s - 1];
	return s;
}

kill(pid: int)
{
	fd := sys->open(sprint("/prog/%d/ctl", pid), sys->OWRITE);
	sys->fprint(fd, "kill");
}

reader(fd: ref Sys->FD, ch: chan of (array of byte, string), waitch: chan of int)
{
	buf := array[Sys->ATOMICIO] of byte;
	for(;;) {
		n := sys->read(fd, buf, len buf);
		if(n < 0)
			ch <-= (nil, sprint("reading: %r"));
		if(n == 0)
			ch <-= (nil, nil);
		if(n <= 0)
			return;
		ch <-= (buf[:n], nil);
		<- waitch;
	}
}

ticker(ch, pidch: chan of int)
{
	pidch <-= sys->pctl(0, nil);
	for(;;) {
		sys->sleep(3*1000);
		ch <-= 0;
	}
}

readbody(): array of byte
{
	fd := sys->fildes(0);
	a := array[0] of byte;
	buf := array[Sys->ATOMICIO] of byte;

	for(;;) {
		n := sys->read(fd, buf, len buf);
		if(n < 0)
			fail(sprint("reading body: %r"));
		if(n == 0)
			break;
		anew := array[len a+n] of byte;
		anew[:] = a;
		anew[len a:] = buf[:n];
		a = anew;
	}
	return a;
}

killgrp()
{
	fd := sys->open("/prog/"+string sys->pctl(0, nil)+"/ctl", sys->OWRITE);
	if(fd != nil)
		sys->fprint(fd, "killgrp\n");
}

fail(s: string)
{
	killgrp();
	warn(s);
	raise "fail:"+s;
}

warn(s: string)
{
	sys->fprint(sys->fildes(2), "%s\n", s);
}

say(s: string)
{
	if(dflag)
		warn(s);
}
