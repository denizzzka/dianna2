@safe:

import ecdsa;
import records;
import storage;

import dproto.dproto;

import std.conv: to;
import std.encoding;


@trusted mixin ProtocolBuffer!"dnsvalue.proto";

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
    
    // TODO: also need serial number of dns record
    
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
    
    private static ubyte[] getString(ubyte[] from, ref size_t offset)
    {
        const len = from[offset];
        
        const start = offset + 1;
        offset += 1 + len;
        
        return from[start..offset];
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
    
    d1.key = "key data";
    d1.skv.payload = cast(ubyte[]) "value data";
    d1.signature.pubKey[0] = 0xAA;
    
    auto ser = d1.serialize();
    
    auto d2 = DNSValue.deserialize(ser);
    
    assert(d1.key == d2.key);
    assert(d1.skv.payload == d2.skv.payload);
    assert(d1.signature == d2.signature);
}
