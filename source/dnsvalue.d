@safe:

import ecdsa;
import records;
import storage;

import protobuf;

import std.conv: to;
import std.encoding;
import std.socket;
import std.typecons: Tuple;
import std.bitmanip: nativeToBigEndian, bigEndianToNative;
import std.json;


struct DNSValue
{
    Signed pb;
    alias pb this;
    
    string key(string key) @trusted
    {
        pb.keyValue.key = cast(ubyte[]) key;
        
        return key;
    }
    
    string key() @trusted
    {
        return cast(string) pb.keyValue.key;
    }
    
    void sign(in string filename) @trusted
    {
        const digest = pb.keyValue.serialize();
        const hash = calcSHA1Hash(digest);
        
        pb.signature = ecdsa.sign(hash, filename);
    }
    
    string toString()
    {
        return format("key=%s value=%s", key, pb.keyValue.payload.toString());
    }
    
    private static ubyte[] string2networkAddr(in string addrString) @trusted
    {
        const a = parseAddress(addrString);
        
        ubyte[] res;
        switch(a.addressFamily)
        {
            case AddressFamily.INET6:
                res = Internet6Address.parse(addrString); // FIXME: addr to network byte order
                break;
            
            case AddressFamily.INET:
                const uint ipv4 = InternetAddress.parse(addrString);
                res = nativeToBigEndian(ipv4);
                break;
            
            default:
                enforce(false, "Unsupported address type");
                break;
        }
        
        return res;
    }
    
    private static string networkAddr2string(ubyte[] addr) @trusted
    {
        string res;
        
        switch(addr.length)
        {
            case 16:
                ubyte[16] b = addr[0..16];
                const ipv6 = new Internet6Address(b, Internet6Address.PORT_ANY); // FIXME: need to change byte order
                res = ipv6.toAddrString();
                break;
            
            case 4:
                ubyte[4] b = addr[0..4];
                const ipv4 = new InternetAddress(bigEndianToNative!uint(b), InternetAddress.PORT_ANY);
                res = ipv4.toAddrString();
                break;
            
            default:
                enforce(false, "Unsupported address type");
                break;                
        }
        
        return res;
    }
    
    unittest
    {
        const ipv4str = "192.0.2.235";
        const ipv6str = "2001:db8::";
        
        assert(networkAddr2string(string2networkAddr(ipv4str)) == ipv4str);
        assert(networkAddr2string(string2networkAddr(ipv6str)) == ipv6str);
    }
    
    static DNSValue fromJson(in JSONValue j, in string keypath) @trusted
    {
        DNSValue r;
        
        r.key = j["domain"].str;
        
        const type = j["type"].str;
        if(type == "announce") r.keyValue.flags &= RecordFlags.Announce;
        if(type == "cancel") r.keyValue.flags &= RecordFlags.Cancel;
        
        const ns = j["NS"].array;
        DNSPayload payload;
        foreach(ref s; ns)
            payload.ns ~= string2networkAddr(s.str);
        
        r.keyValue.payload = payload.serialize();
        
        r.sign(keypath);
        
        return r;
    }
    
    JSONValue toJson() @trusted
    {
        JSONValue j;
        
        {
            //auto v = Json(key);
            //v.name = "domain";
            //j ~= v;
        }
        /*
        {
            Json v;
            v.name = "type";
            
            if(keyValue.flags & RecordFlags.Announce)
                v = "announce";
            
            if(keyValue.flags & RecordFlags.Cancel)
                v = "cancel";
            
            if(v != Json.undefined) j ~= v;
        }
        
        DNSPayload dnsp;
        dnsp.deserialize(keyValue.payload);
        
        {
            Json v = Json.emptyArray;
            v.name = "NS";
            
            foreach(ref r; dnsp.ns)
                v = networkAddr2string(r);
            
            j ~= v;
        }
        */
        return j;
    }
}

DNSValue[] followByChain(
    Storage s,
    in ChainType chainType,
    in string key
)
{
    DNSValue[] dnsRecords;
    
    bool fillRecords(ref Record r)
    {
        DNSValue d;
        d.deserialize(r.payload);
        
        if(d.key == key)
        {
            dnsRecords ~= d;
            
            return d.pb.keyValue.flags != RecordFlags.Announce;
        }
        
        return true;
    }
    
    s.followByChain(chainType, PayloadType.DNS, &fillRecords);
    
    return dnsRecords;
}

@trusted unittest
{
    import std.file: remove;
    
    
    DNSValue d1;
    
    d1.key = "key data";
    d1.pb.keyValue.payload = cast(ubyte[]) "value data";
    PubKey pk;
    pk[0] = 0xAA;
    d1.signature.pubKey = pk;
    
    auto ser = d1.serialize();
    
    DNSValue d2;
    d2.deserialize(ser);
    
    assert(d1.key == d2.key);
    assert(d1.pb.keyValue.payload == d2.pb.keyValue.payload);
    assert(d1.signature == d2.signature);
    
    const keypath = "/tmp/_unittest_dnsvalue.pem";
    createKeyPair(keypath);
    DNSValue v = DNSValue.fromJson(parseJSON(`
        {
            "type": "announce",
            "domain": "domain-name",
            "NS": [
                "192.0.2.235",
                "0xC0.0x00.0x02.0xEB",
                "0300.0000.0002.0353",
                "0xC00002EB",
                "3221226219",
                "030000001353",
                
                "2001:db8::",
                "fe80:0:0:0:200:f8ff:fe21:67cf",
                "fe80::200:f8ff:fe21:67cf"
            ],
            "DS": [
                "2BB183AF5F22588179A53B0A98631FAD1A292118",
                "BROKENFINGERPRINTAAAAAAAAAAAAAAAAAAAAAAA"
            ]
        }
    `), keypath);
    remove(keypath);
    
    assert(v.key == "domain-name");
    assert(v.keyValue.flags & RecordFlags.Announce);
    assert(!(v.keyValue.flags & RecordFlags.Cancel));
    
    import std.stdio;
    writeln(v.toJson.toPrettyString);
}
