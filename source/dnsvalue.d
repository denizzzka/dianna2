@safe:

import ecdsa;
import records: calcSHA1Hash;

import std.conv: to;


struct DNSValue
{
    ubyte[] key;
    ubyte[] value;
    
    Signature signature;
    
    // TODO: also need serial number of dns record
    
    void sign(in string filename)
    {
        const hash = calcSHA1Hash(getUbytes());
        
        signature = ecdsa.sign(hash, filename);
    }
    
    ubyte[] serialize() const
    {
        auto res = getUbytes();
        res ~= signature.serialize();
        
        return res;
    }
    
    private ubyte[] getUbytes() const
    {
        ubyte[] res;
        
        res ~= to!ubyte(key.length);
        res ~= key;
        
        res ~= to!ubyte(value.length);
        res ~= value;
        
        return res;
    }
    
    static DNSValue deserialize(ubyte[] from)
    {
        DNSValue res;
        size_t offset;
        
        res.key = getString(from, offset);
        res.value = getString(from, offset);
        res.signature = Signature.deserialize(from[offset..$]);        
        
        return res;
    }
    
    private static ubyte[] getString(ubyte[] from, ref size_t offset)
    {
        const len = from[offset];
        
        const start = offset + 1;
        offset += 1 + len;
        
        return from[start..offset];
    }
}

@trusted unittest
{
    
    DNSValue d1;
    
    d1.key = cast(ubyte[]) "key data";
    d1.value = cast(ubyte[]) "value data";
    d1.signature.pubKey[0] = 0xAA;
    
    auto ser = d1.serialize();
    
    auto d2 = DNSValue.deserialize(ser);
    
    assert(d1.key == d2.key);
    assert(d1.value == d2.value);
    assert(d1.signature == d2.signature);
}
