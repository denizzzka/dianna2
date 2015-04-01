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
import std.format: formattedRead, format;


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
                res ~= Internet6Address.parse(addrString); // FIXME: addr to network byte order
                break;
            
            case AddressFamily.INET:
                const uint ipv4 = InternetAddress.parse(addrString);
                res ~= nativeToBigEndian(ipv4);
                break;
            
            default:
                enforce(false, "Unsupported address type");
                break;
        }
        
        return res;
    }
    
    private static string networkAddr2string(in ubyte[] addr) @trusted
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
    
    static DNSValue fromJSON(in JSONValue j) @trusted
    {
        DNSValue r;
        
        r.key = j["domain"].str;
        
        if("type" in j)
        {
            const type = j["type"].str;
            if(type == "announce") r.keyValue.flags &= RecordFlags.Announce;
            if(type == "cancel") r.keyValue.flags &= RecordFlags.Cancel;
        }
        
        DNSPayload payload;
        
        if("NS" in j)
            foreach(i, ref s; j["NS"].array)
                payload.ns ~= string2networkAddr(s.str);
        
        r.keyValue.payload = payload.serialize();
        
        if("signature" in j)
        {
            r.signature.signature = hex2bytes(j["signature"]["signature"].str);
            r.signature.pubKey = hex2bytes(j["signature"]["pubKey"].str);
        }
        
        return r;
    }
    
    JSONValue toJSON() @trusted
    {
        JSONValue j = ["domain": key];
        
        DNSPayload dnsp;
        dnsp.deserialize(keyValue.payload);
        
        {
            string[] ns;
            
            foreach(r; dnsp.ns)
                ns ~= networkAddr2string(r);
            
            j.object["NS"] = ns;
        }
        
        {
            JSONValue sig = ["signature": bytes2hex(signature.signature)];
            sig.object["pubKey"] = bytes2hex(signature.pubKey);
            
            j.object["signature"] = sig;
        }
        
        return j;
    }
}

ubyte[] hex2bytes(string s) @trusted
{
    enforce(s.length % 2 == 0);
    
    ubyte[] res = new ubyte[s.length/2];
    
    for(auto i = 0; i < s.length; i += 2)
    {
        string slice = s[i..i+2];
        slice.formattedRead("%x", &res[i/2]);
    }
    
    return res;
}

string bytes2hex(in ubyte[] b)
{
    return format("%(%02X%)", b);
}

unittest
{
    assert(hex2bytes("0102fe") == [1, 2, 254]);
    assert(bytes2hex([1, 2, 254]) == "0102FE");
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
    
    Signature.ECSign sig;
    sig[0] = 0xBB;
    
    d1.pb.signature.signature = sig;
    d1.pb.signature.pubKey = pk;
    
    auto ser = d1.serialize();
    
    DNSValue d2;
    d2.deserialize(ser);
    
    assert(d1.key == d2.key);
    assert(d1.pb.keyValue.payload == d2.pb.keyValue.payload);
    assert(d1.signature == d2.signature);
    
    const keypath = "/tmp/_unittest_dnsvalue.pem";
    createKeyPair(keypath);
    DNSValue v = DNSValue.fromJSON(parseJSON(`
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
            ],
            "signature":
            {
                "signature": "1122334455667788",
                "pubKey": "001122334455"
            }
        }
    `));
    remove(keypath);
    
    assert(v.key == "domain-name");
    assert(v.keyValue.flags & RecordFlags.Announce);
    assert(!(v.keyValue.flags & RecordFlags.Cancel));
    
    import std.stdio;
    writeln(v.toJSON.toPrettyString);
}
