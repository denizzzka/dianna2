@safe:

import ecdsa;
import records;
import storage;

import protobuf;

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
    
    void sign(in string filename)
    {
        const hash = calcSHA1Hash(getUbytes());
        
        pb.signature = ecdsa.sign(hash, filename);
    }
    
    private ubyte[] getUbytes()
    {
        ubyte[] res;
        
        res ~= to!ubyte(key.length);
        res ~= key;
        
        res ~= to!ubyte(pb.keyValue.payload.length);
        res ~= pb.keyValue.payload;
        
        return res;
    }
    
    string toString()
    {
        return format("key=%s value=%s", key, pb.keyValue.payload.toString());
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
}
