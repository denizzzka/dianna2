@safe:

import ecdsa;
import records;
import storage;

import protobuf;
import vibe.data.json;

import std.conv: to;
import std.encoding;
import std.socket;
import std.typecons: Tuple;
import std.bitmanip: nativeToBigEndian;


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
    
    private static IPProto addr2network(in string addrString, out ubyte[] res) @trusted
    {
        const addr = parseAddress(addrString);
        
        IPProto proto;
        switch(addr.addressFamily)
        {
            case AddressFamily.INET:
                proto = IPProto.IPv4;
                break;
            
            case AddressFamily.INET6:
                proto = IPProto.IPv6;
                break;
            
            default:
                enforce(false, "Unsupported address type");
                break;
        }
        
        if(proto == IPProto.IPv6)
            res = Internet6Address.parse(addrString);
        else
        {
            const uint ipv4 = InternetAddress.parse(addrString);
            res ~= nativeToBigEndian(ipv4);
        }
        
        return proto;
    }
    
    static DNSValue fromJson(in Json j, in string keypath) @trusted
    {
        DNSValue r;
        
        r.key = j["domain"].get!string;
        
        const type = j["type"].get!string;
        if(type == "announce") r.keyValue.flags &= RecordFlags.Announce;
        if(type == "cancel") r.keyValue.flags &= RecordFlags.Cancel;
        
        const ns = j["NS"].get!(Json[]);
        DNSPayload payload;
        foreach(ref s; ns)
        {
            ubyte[] addr;
            const proto = addr2network(s.get!string, addr);
            
            NS _ns;
            
            _ns.addr = addr;
            _ns.ip_proto = proto;
            
            payload.ns ~= _ns;
        }
        
        r.keyValue.payload = payload.serialize();
        
        r.sign(keypath);
        
        return r;
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
    DNSValue v = DNSValue.fromJson(parseJsonString(`
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
}
