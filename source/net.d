import std.stdio;
import std.conv;
import std.exception : enforce;

import miniupnpc;
import miniupnpc.upnpcommands;


unittest
{
    UPNPDev* upnp;
    int err;
    upnp = enforce(upnpDiscover(2000, null, null, false, false, &err));

    scope(exit) if(upnp) freeUPNPDevlist(upnp);

    UPNPUrls urls;
    IGDdatas data;
    char[32] lanaddr;
    UPNP_GetValidIGD(upnp, &urls, &data, lanaddr.ptr, lanaddr.length.to!int);

    char[32] addr;
    UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype.ptr, addr.ptr);

    writeln("LAN Address : ", lanaddr.ptr.to!string);
    writeln("External IP Address : ", addr.ptr.to!string);
}
