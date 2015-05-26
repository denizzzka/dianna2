@trusted:

import inifiled;
import std.path: expandTilde;
import std.exception;


@INI("Main section")
private struct Config {
    @INI("Local addresses, IP and IPv6 is allowed")
    string[] listen_addresses = ["::"];
    
    @INI("Local port number")
    ushort listen_port = 60180;
    
    /// Listening enabled?
    bool listen() const
    {
        return listen_addresses.length != 0;
    }
    
    @INI("Enable UPnP")
    bool upnp = true;
    
    @INI("Maintain at most <n> inbound connections to peers")
    max_inbound_connections = 8;
    
    @INI("Local storage dir")
    string storageDir = "~/.dianna2";
    
    @INI("maxReceiveBuffer")
    size_t maxReceiveBuffer = 5;
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
