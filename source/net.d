import config;
import peersstorage;

import miniupnpc;
import miniupnpc.upnpcommands;

import std.stdio;
import std.conv;
import std.exception : enforce;
import std.socket;
debug import std.stdio; //FIXME: remove it


TcpSocket createListener()
{
    auto s = new TcpSocket(AddressFamily.INET6);
    enforce(s.isAlive);
    
    s.setOption(SocketOptionLevel.IPV6, SocketOption.IPV6_V6ONLY, false);
    s.setKeepAlive(60 * 3, 30);
    s.blocking = false;
    
    foreach(ref c; cfg.listen_addresses)
        s.bind(new Internet6Address(c, cfg.listen_port));
    
    s.listen(cfg.max_inbound_connections);
    
    writefln("Listening on port %d.", cfg.listen_port);
    
    return s;
}

unittest
{
    auto listener = createListener();
    
    auto socketSet = new SocketSet(cfg.max_inbound_connections + 1);
    socketSet.add(listener);
    
    Socket[] reads;
    
    while (true)
    {
        foreach (sock; reads)
            socketSet.add(sock);
        
        Socket.select(socketSet, null, null);
        
        for (size_t i = 0; i < reads.length; i++)
        {
            if (socketSet.isSet(reads[i]))
            {
                char[1024] buf;
                auto datLength = reads[i].receive(buf[]);
                
                if (datLength == Socket.ERROR)
                    writeln("Connection error.");
                else if (datLength != 0)
                {
                    writefln("Received %d bytes from %s: \"%s\"", datLength, reads[i].remoteAddress().toString(), buf[0..datLength]);
                    continue;
                }
                else
                {
                    try
                    {
                        // if the connection closed due to an error, remoteAddress() could fail
                        writefln("Connection from %s closed.", reads[i].remoteAddress().toString());
                    }
                    catch (SocketException)
                    {
                        writeln("Connection closed.");
                    }
                }
                
                // release socket resources now
                reads[i].close();
                
                reads = reads[0..i]~reads[i+1..$]; // FIXME: this statement isn't compiles: reads.remove(i);
                // i will be incremented by the for, we don't want it to be.
                i--;
                
                writefln("\tTotal connections: %d", reads.length);
            }
        }
        
        if (socketSet.isSet(listener))        // connection request
        {
            Socket sn = listener.accept();
            scope (failure)
            {
                writefln("Error accepting");
                
                if (sn)
                    sn.close();
            }
            assert(sn.isAlive);
            assert(listener.isAlive);
            
            if (reads.length < cfg.max_inbound_connections)
            {
                writefln("Connection from %s established.", sn.remoteAddress().toString());
                reads ~= sn;
                writefln("\tTotal connections: %d", reads.length);
            }
            else
            {
                writefln("Rejected connection from %s; too many connections.", sn.remoteAddress().toString());
                sn.close();
                assert(!sn.isAlive);
                assert(listener.isAlive);
            }
        }
        
        socketSet.reset();
    }
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
