import config;
import peersstorage;

import vibe.core.net;

import miniupnpc;
import miniupnpc.upnpcommands;

import std.stdio;
import std.conv;
import std.exception : enforce;
import std.socket;
debug import std.stdio; //FIXME: remove it


version(unittest)
shared static this()
{
    listenTCP(60800, (conn){ conn.write(conn); }, "::");
}

unittest
{
    int err;
    UPNPDev* upnp = upnpDiscover(2000, null, null, false, false, &err);
    
    scope(exit) if(upnp) freeUPNPDevlist(upnp);
    
    if(!upnp)
    {
        writeln("UPnP discovery failed");
    }
    else
    {
        UPNPUrls urls;
        IGDdatas data;
        char[32] lanaddr;
        UPNP_GetValidIGD(upnp, &urls, &data, lanaddr.ptr, lanaddr.length.to!int);
        
        char[32] addr;
        UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype.ptr, addr.ptr);
        
        writeln("LAN Address : ", lanaddr.ptr.to!string);
        writeln("External IP Address : ", addr.ptr.to!string);
    }
}
