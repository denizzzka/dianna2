@safe:

import ecdsa;
import records;
import storage;

import protobuf;

import std.conv: to;
import std.encoding;


struct DNSValue
{
    SignedKeyValue skv;
    
    string key(string key) @trusted
    {
        skv.key = cast(ubyte[]) key;
        
        return key;
    }
    
    string key() @trusted
    {
        return cast(string) skv.key;
    }
    
    Signature signature;
    
    void sign(in string filename)
    {
        const hash = calcSHA1Hash(getUbytes());
        
        signature = ecdsa.sign(hash, filename);
    }
    
    ubyte[] serialize()
    {
        skv.signature = signature.serialize();
        
        return skv.serialize();
    }
    
    private ubyte[] getUbytes()
    {
        ubyte[] res;
        
        res ~= to!ubyte(key.length);
        res ~= key;
        
        res ~= to!ubyte(skv.payload.length);
        res ~= skv.payload;
        
        return res;
    }
    
    static DNSValue deserialize(ubyte[] from)
    {
        DNSValue res;
        
        res.skv = SignedKeyValue(from);
        res.signature = Signature.deserialize(res.skv.signature);
        
        return res;
    }
    
    string toString()
    {
        return format("key=%s value=%s", key, skv.payload.toString());
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
        DNSValue dnsValue = DNSValue.deserialize(r.payload);
        
        dg(r, dnsValue);
    }
}

@trusted unittest
{
    
    DNSValue d1;
    
    d1.key = "key data";
    d1.skv.payload = cast(ubyte[]) "value data";
    d1.signature.pubKey[0] = 0xAA;
    
    auto ser = d1.serialize();
    
    auto d2 = DNSValue.deserialize(ser);
    
    assert(d1.key == d2.key);
    assert(d1.skv.payload == d2.skv.payload);
    assert(d1.signature == d2.signature);
}
