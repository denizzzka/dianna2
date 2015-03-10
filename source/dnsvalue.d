@safe:

import ecdsa;
import records;
import storage;

import vibe.data.json;

import std.conv: to;
import std.encoding;


struct DNSValue
{
    ubyte[] key;
    ubyte[] value;
    
    Signature signature;
    
    // TODO: also need serial number of dns record
    
    string key2string() const @trusted
    {
        return cast(string) key;
    }
    
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
    
    string toString() const
    {
        return format("key=%s value=%s", key2string(), value.toString());
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

enum DNSRecordType: ubyte
{
    NS, /// IP address of an authoritative name server
    DS, /// Delegation signer. Fingerprint of the DNSSEC signing key of a delegated zone.
    TOR,
    I2P
}

/** TODO: describe records types:
 * announcing,
 * cancellation,
 * key assignee,
 * key changing,
 * authority transfer
*/

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
