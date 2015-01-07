@safe:

import std.datetime;
import std.conv;
import std.digest.sha;
import std.typecons;
import scrypt;


enum ChainType
{
    Real,
    Test
}

alias SHA1_hash = ubyte[20];
alias BlockHash = SHA1_hash;
alias PoW = ubyte[64];

struct Record
{
    ChainType chainType;
    ubyte[] key;
    ubyte[] value;
    ubyte[10] signature;
    uint blockNum;
    BlockHash prevFilledBlock;
    PoW proofOfWork;
    
    ubyte[] serialize() const
    {
        ubyte[] res;
        
        res ~= to!string(chainType);
        res ~= key ~ value;
        res ~= signature;
        res ~= to!string(blockNum);
        res ~= prevFilledBlock;
        res ~= proofOfWork;
        
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

BlockHash calcBlockHash(inout Record[] records)
{
    SHA1 hash;
    
    foreach(r; records)
    {
        hash.put(r.serialize);
    }
    
    return cast(BlockHash) hash.finish;
}

PoW calcProofOfWork(SHA1_hash from, ubyte[] difficulty, long iterations)
{
    PoW res;
    
    calcScrypt(res, from, [], 65536, 64, 1);
    
    return res;
}

unittest
{
    Record[10] r;
    auto h = calcBlockHash(r);
    
    ubyte[8] salt;
    genSalt(salt);
    
    auto proof = calcProofOfWork(h, salt, 1);
}
