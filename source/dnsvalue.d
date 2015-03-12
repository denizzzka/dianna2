@safe:

import ecdsa;
import records;
import storage;

import protobuf;
import vibe.data.json;

import std.conv: to;
import std.encoding;


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
    
    static DNSValue fromJson(in Json j, in string keypath) @trusted
    {
        DNSValue r;
        
        r.key = j["domain"].get!string;
        
        const type = j["type"].get!string;
        if(type == "announce") r.keyValue.flags &= RecordFlags.Announce;
        if(type == "cancel") r.keyValue.flags &= RecordFlags.Cancel;
        
        const ns = j["NS"].get!(Json[]);
        DNSPayload payload;
        //foreach(ref r; ns)
        //{
        //
        //payload
        
        r.sign(keypath);
        
        return r;
    }
}

void followByChain(
    Storage s,
    in ChainType chainType,
    in string key,
    void delegate(ref Record, ref DNSValue) @safe dg
)
{
    Record[] records;
    
    bool fillRecords(ref Record r)
    {
        records ~= r;
        
        return true;
    }
    
    s.followByChain(chainType, PayloadType.DNS, &fillRecords);
    
    foreach_reverse(ref r; records)
    {
        DNSValue dnsValue;
        dnsValue.deserialize(r.payload);
        
        dg(r, dnsValue);
    }
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
                "192.168.0.1",
                "192.168.0.2",
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
