@safe:

import ecdsa;

import std.conv: to;


struct DNSValue
{
    ubyte[] key;
    ubyte[] value;
    
    Signature signature;
    
    ubyte[] serialize() const
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
    
    auto ser = d1.serialize();
    
    auto d2 = DNSValue.deserialize(ser);
    
    assert(d1.key == d2.key);
    assert(d1.value == d2.value);
}
