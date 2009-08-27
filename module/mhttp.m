Http: module
{
	PATH:	con "/dis/lib/mhttp.dis";

	init:	fn(bufio: Bufio);
	debug:	int;

	HTTP_10, HTTP_11:	con iota;
	UNKNOWN, OPTIONS, GET, HEAD, POST, PUT, DELETE, TRACE, CONNECT, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK:	con iota;

	get:	fn(u: ref Url, h: ref Hdrs): (ref Req, ref Resp, ref Sys->FD, string);
	#post:	fn(url: ref Url, hdrs: list of (string, string), data: array of byte): (ref Rbuf, string);
	#retrieve:	fn(req: ref Request): (ref Response, string);
	#request:	fn(req: ref Request): (ref Response, string);

	encodequery:	fn(s: string): string;
	encodepath:	fn(s: string): string;
	decode:		fn(s: string): string;

	basicauth:	fn(user, pass: string): (string, string);
	status:	fn(r: ref Resp): string;

	isidempotent:	fn(method: int): int;

	methodstr:	fn(method: int): string;
	versionstr:	fn(version: int): string;

	Url: adt {
		usessl: int;
		scheme, host, port, path, query: string;

		pack:	fn(u: self ref Url): string;
		packpath:	fn(u: self ref Url): string;
		unpack:	fn(s: string): (ref Url, string);
		addr:	fn(u: self ref Url): string;
	};

	Req: adt {
		method:	int;
		methodstr: string;
		url:	ref Url;
		major, minor:	int;
		h:	ref Hdrs;

		body:	array of byte;
		proxyaddr:	string;

		mk:	fn(method: int, url: ref Url, version: int, h: ref Hdrs): ref Req;
		pack:	fn(r: self ref Req): string;
		write:	fn(r: self ref Req, fd: ref Sys->FD): string;
		read:	fn(b: ref Bufio->Iobuf): (ref Req, string);
		dial:	fn(u: self ref Req): (ref Sys->FD, string);
		version:	fn(r: self ref Req): int;
	};

	Resp: adt {
		major, minor:	int;
		st, stmsg:	string;
		h:	ref Hdrs;

		mk:	fn(version: int, st, stmsg: string, h: ref Hdrs): ref Resp;
		pack:	fn(r: self ref Resp): string;
		write:	fn(r: self ref Resp, fd: ref Sys->FD): string;
		read:	fn(b: ref Bufio->Iobuf): (ref Resp, string);
		hasbody:	fn(r: self ref Resp, reqmethod: int): int;
		body:	fn(r: self ref Resp, b: ref Bufio->Iobuf): (ref Sys->FD, string);
		version:	fn(r: self ref Resp): int;
	};

	Hdrs: adt {
		l:	list of (string, string);

		new:	fn(l: list of (string, string)): ref Hdrs;
		read:	fn(b: ref Bufio->Iobuf): (ref Hdrs, string);
		set:	fn(h: self ref Hdrs, k, v: string);
		add:	fn(h: self ref Hdrs, k, v: string);
		del:	fn(h: self ref Hdrs, k, v: string);
		find:	fn(h: self ref Hdrs, k: string): (int, string);
		findall:	fn(h: self ref Hdrs, k: string): list of string;
		get:	fn(h: self ref Hdrs, k: string): string;
		getlist:	fn(h: self ref Hdrs, k: string): string;
		has:	fn(h: self ref Hdrs, k, v: string): int;
		all:	fn(h: self ref Hdrs): list of (string, string);
	};
};
