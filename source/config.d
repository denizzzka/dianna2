@trusted:

import inifiled;
import std.path: expandTilde;
import std.exception;


@INI("Main section")
private struct Config {
    @INI("Local addresses. IP and IPv6 is allowed, port is required."~
	 "Example: :::60180 - bind to all local addresses and port 60180")
    string[] listen_addresses = [":::60180", ":::60181"];
}

private Config _cfg;

ref const (Config) cfg()
{
    return _cfg;
}

static this()
{
    try
	readINIFile(_cfg, "/etc/dianna2.conf");
    catch(ErrnoException e)
    {}
    
    try
	readINIFile(_cfg, expandTilde("~/.config/dianna2/dianna2.conf"));
    catch(ErrnoException e)
    {}
}
