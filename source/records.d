@safe:

import std.datetime;
import std.conv;
import std.digest.sha;
import std.bitmanip;
import std.random: uniform;
import scrypt: calcScrypt;
import std.file: read;
import std.exception: enforce;


enum ChainType: ushort
{
    Real,
    Test
}

enum PayloadType: ushort
{
    Test = 1,
    DNS
}

struct HashT(T)
{
    alias Hash = T;
    alias Salt = ubyte[8];
    
    Hash hash;
    Salt salt;
    static immutable length = Hash.length + Salt.length;
    
    auto getUbytes() const pure
    {
        immutable ubyte[length] res = hash ~ salt;
        return res;
    }
    
    this(ubyte[length] s)
    {
        hash = s[0..Hash.length];
        salt = s[Hash.length..$];
    }
    
    static HashT createFrom(ubyte[] s)
    {
        enforce(s.length == length);
        
        return HashT(s[0..length]);
    }
    
    static Salt genSaltFast() @trusted
    {
        Salt res;
        
        foreach(ref e; res)
            e = uniform!ubyte;
        
        return res;
    }
    
    static Salt genSaltExpensive() @trusted
    {
        Salt res;
        
        res = cast(ubyte[]) read("/dev/urandom", Salt.sizeof);
        
        return res;
    }
}

alias SHA1Hash = HashT!(ubyte[20]);
alias PoW = HashT!(ubyte[32]);
alias RecordHash = SHA1Hash;
alias BlockHash = SHA1Hash;
alias Signature = ubyte[10];
alias Difficulty = ulong;

ulong extractTarget(in PoW.Hash h) pure @nogc
{
    immutable offset = h.length - ulong.sizeof;
    
    immutable ubyte[ulong.sizeof] arr = h[offset..offset + ulong.sizeof];
    
    return littleEndianToNative!ulong(arr);
}

unittest
{
    PoW pow;
    
    assert(pow.hash.extractTarget() == 0);
    
    pow.hash[24] = 1;
    
    assert(pow.hash.extractTarget() == 1);
    
    foreach(i; 24..32)
        pow.hash[i] = 0xff;
    
    assert(pow.hash.extractTarget() == ulong.max);
    
    pow.hash[24] = 1;
    
    assert(pow.hash.extractTarget() < ulong.max);
    assert(pow.hash.extractTarget() > 1);
}

struct Record
{
    ChainType chainType;
    PayloadType payloadType;
    ubyte[] payload;
    RecordHash hash;
    uint blockNum;
    BlockHash prevFilledBlock;
    PoW proofOfWork;
    Difficulty difficulty;
    
    this(this) pure
    {
        payload = payload.dup;
    }
    
    RecordHash calcPayloadHash() const
    {
        ubyte[] b;
        
        b ~= to!string(chainType);
        b ~= to!string(payloadType);
        b ~= payload;
        
        return b.calcSHA1Hash(RecordHash.genSaltExpensive());
    }
    
    ubyte[] getFullRecordHashSource() const pure
    {
        ubyte[] res;
        
        res ~= hash.getUbytes;
        res ~= to!string(blockNum);
        res ~= prevFilledBlock.getUbytes;
        res ~= to!string(difficulty);
        
        return res;
    }
}

SHA1Hash calcSHA1Hash(inout ubyte[] from, inout SHA1Hash.Salt salt) pure
{
    SHA1Hash res;
    
    SHA1 _hash;
    _hash.put(from);
    _hash.put(salt);
    
    res.hash = _hash.finish;
    res.salt = salt;
    
    return res;
}

immutable half_block_duration_hours = 12;

uint calcCurrentFilledBlockNum()
{
    uint hours = to!uint(Clock.currTime.toUnixTime / 3600);
    return hours / half_block_duration_hours - 2;
}

unittest
{
    assert(calcCurrentFilledBlockNum > 32800);
}

PoW.Hash calcPoWHash(
    inout ubyte[] from,
    inout PoW.Salt salt
) pure
{
    immutable SHA1Hash firstHash = from.calcSHA1Hash(salt);
    
    PoW.Hash result;
    
    calcScrypt(result, firstHash.getUbytes, null, 65536, 64, 1);
    
    return result;
}

bool isValidPoW(inout ubyte[] from, inout PoW pow)
{
    PoW calculatedPow;
    calculatedPow.salt = pow.salt;
    
    calculatedPow.hash = calcPoWHash(from, calculatedPow.salt);
    
    return calculatedPow.hash == pow.hash;
}

bool isSatisfyDifficulty(inout PoW.Hash pow, inout Difficulty d) pure @nogc
{
    return pow.extractTarget() >= d;
}

unittest
{
    Record r;
    immutable src = r.getFullRecordHashSource();
    
    PoW proof;
    immutable Difficulty smallDifficulty = 5;
    
    do{
        proof.salt = PoW.genSaltFast();
        proof.hash = calcPoWHash(src, proof.salt);
    }
    while(
        !isSatisfyDifficulty(proof.hash, smallDifficulty)
    );
    
    assert(isValidPoW(src, proof));
    assert(isSatisfyDifficulty(proof.hash, smallDifficulty));
    
    ubyte[] zeroes = [0, 0, 0, 0];
    assert(src != zeroes);
    assert(!isValidPoW(zeroes, proof));
}
