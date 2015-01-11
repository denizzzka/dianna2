@safe:

import std.datetime;
import std.conv;
import std.digest.sha;
import std.bitmanip;
import scrypt;


enum ChainType: ushort
{
    Real,
    Test
}

enum RecordType: ushort
{
    DNS = 1
}

struct Hash(T)
{
    alias Hash = T;
    alias Salt = ubyte[8];
    
    Hash hash;
    Salt salt;
    
    auto getUbytes() const pure
    {
        immutable ubyte[Hash.sizeof + Salt.sizeof] res = hash ~ salt;
        return res;
    }
    
    void fillSalt()
    {
        genSalt(salt);
    }
}

alias SHA1Hash = Hash!(ubyte[20]);
alias PoW = Hash!(ubyte[32]);
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
    ubyte[] key;
    ubyte[] value;
    uint blockNum;
    BlockHash prevFilledBlock;
    PoW proofOfWork;
    Difficulty difficulty;
    
    this(this) pure
    {
        key = key.dup;
        value = value.dup;
    }
    
    ubyte[] serialize() const pure
    {
        ubyte[] res;
        
        res ~= to!string(chainType);
        res ~= key ~ value;
        res ~= to!string(blockNum);
        res ~= prevFilledBlock.getUbytes;
        res ~= proofOfWork.hash;
        res ~= proofOfWork.salt;
        res ~= to!string(difficulty);
        
        return res;
    }
    
    RecordHash calcHash() const pure
    {
        SHA1 hash;
        RecordHash res;
        
        res.fillSalt();
        
        hash.put(res.salt);
        hash.put(serialize);
        
        res.hash = hash.finish;
        
        return res;
    }
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

@disable
BlockHash calcBlockHash(inout Record[] records) pure
{
    SHA1 hash;
    BlockHash res;
    
    res.fillSalt();
    hash.put(res.salt);
    
    foreach(ref r; records)
        hash.put(r.serialize);
        
    res.hash = hash.finish;
    
    return res;
}

PoW.Hash calcPoWHash(
    inout SHA1Hash from,
    inout PoW.Salt salt
) pure
{
    SHA1 sha1Hasher;
    sha1Hasher.put(from.hash);
    sha1Hasher.put(from.salt);
    sha1Hasher.put(salt);
    immutable ubyte[20] sha1Hash = sha1Hasher.finish;
    
    PoW.Hash result;
    calcScrypt(result, sha1Hash, null, 65536, 64, 1);
    
    return result;
}

bool isValidPoW(inout SHA1Hash from, inout PoW pow)
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
    immutable hash = r.calcHash();
    
    PoW proof;
    immutable Difficulty smallDifficulty = 5;
    
    do{
        proof.fillSalt();
        proof.hash = calcPoWHash(hash, proof.salt);
    }
    while(
        !isSatisfyDifficulty(proof.hash, smallDifficulty)
    );
    
    assert(isValidPoW(hash, proof));
    assert(isSatisfyDifficulty(proof.hash, smallDifficulty));
    
    BlockHash zeroHash;
    assert(hash != zeroHash);
    assert(!isValidPoW(zeroHash, proof));
}
