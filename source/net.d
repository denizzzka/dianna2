// Based on the Bitcoin networking code

import config;
import peersstorage;

import vibe.core.net;
import vibe.core.core: runTask;
import vibe.vibe: runEventLoop, exitEventLoop;

import miniupnpc;
import miniupnpc.upnpcommands;

import std.stdio;
import std.socket: Address;
import std.conv;
import std.exception : enforce;
debug import std.stdio; //FIXME: remove it


/** Time between pings automatically sent out for latency probing and keepalive (in seconds). */
immutable ushort pingInterval = 2 * 60;

/** Time after which to disconnect, after waiting for a ping response (or inactivity). */
immutable ushort timeoutInterval = 20 * 60;

/** The maximum number of entries in an 'inv' protocol message */
immutable ushort maxInvNum = 50000;

/** The maximum number of new addresses to accumulate before announcing. */
immutable ushort maxAddrToSend = 1000;

/** Maximum length of incoming protocol messages (no message over 2 MiB is currently acceptable). */
immutable size_t maxProtocolMessageLength = 2 * 1024 * 1024;

/** The maximum number of entries in mapAskFor */
immutable size_t mapAskForMax = maxInvNum;

size_t receiveFloodSize()
{
    return 1000 * cfg.maxReceiveBuffer;
}

size_t sendBufferSize()
{
    return 1000 * cfg.maxSendBuffer;
}

enum AddrGroup
{
    DEFAULT
}

class PeerAddress : Address
{
    /// Get identifier of an address's group
    /// No two connections will be attempted to addresses of the same group
    AddrGroup getAddrGroup() const
    {
        return AddrGroup.DEFAULT;
    }
}

shared static this()
{
    foreach(ref addr; cfg.listen_addresses)
    {
        listenTCP(cfg.listen_port,
                (conn)
                {
                    conn.write(conn);
                },
                addr
            );
    }
    
    runTask(
            {
                // TODO: some networking job here
                
                exitEventLoop();
            }
        );
    
    runEventLoop();
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
