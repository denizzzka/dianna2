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

alias SHA1_hash = ubyte[20];
alias RecordHash = SHA1_hash;
alias BlockHash = SHA1_hash;
alias Signature = ubyte[10];
alias Difficulty = ulong;

struct PoW
{
    alias Hash = ubyte[32];
    alias Salt = ubyte[8];
    
    Hash hash;
    Salt salt;
}

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
    Signature signature;
    uint blockNum;
    BlockHash prevFilledBlock;
    PoW proofOfWork;
    Difficulty difficulty;
    
    this(this)
    {
        key = key.dup;
        value = value.dup;
    }
    
    ubyte[] serialize() const pure
    {
        ubyte[] res;
        
        res ~= to!string(chainType);
        res ~= key ~ value;
        res ~= signature;
        res ~= to!string(blockNum);
        res ~= prevFilledBlock;
        res ~= proofOfWork.hash;
        res ~= proofOfWork.salt;
        res ~= to!string(difficulty);
        
        return res;
    }
    
    RecordHash calcHash() const pure
    {
        SHA1 hash;
        
        hash.put(serialize());
        
        return cast(RecordHash) hash.finish;
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

BlockHash calcBlockHash(inout Record[] records)
{
    SHA1 hash;
    
    foreach(ref r; records)
    {
        hash.put(r.serialize);
    }
    
    return cast(BlockHash) hash.finish;
}

bool tryToCalcProofOfWork(
    inout SHA1_hash from,
    inout Difficulty difficulty,
    inout PoW.Salt salt,
    out PoW pow
) pure
{
    pow.salt = salt;
    calcScrypt(pow.hash, from, pow.salt, 65536, 64, 1);
    
    return isSatisfyDifficulty(pow.hash, difficulty);
}

bool isValidProofOfWork(inout SHA1_hash from, inout PoW pow)
{
    typeof(PoW.hash) calculatedHash;
    
    calcScrypt(calculatedHash, from, pow.salt, 65536, 64, 1);
    
    return calculatedHash == pow.hash;
}

bool isSatisfyDifficulty(inout PoW.Hash pow, inout Difficulty d) pure @nogc
{
    return pow.extractTarget() <= Difficulty.max - d;
}

unittest
{
    Record[10] rec;
    auto hash = calcBlockHash(rec);
    
    PoW proof;
    Difficulty smallDifficulty = 10;
    
    ubyte[8] salt;
    do{
        genSalt(salt);
    }
    while(
        !tryToCalcProofOfWork(hash, smallDifficulty, salt, proof)
    );
    
    assert(isValidProofOfWork(hash, proof));
    assert(isSatisfyDifficulty(proof.hash, smallDifficulty));
    
    BlockHash zeroHash;
    assert(hash != zeroHash);
    assert(!isValidProofOfWork(zeroHash, proof));
}
