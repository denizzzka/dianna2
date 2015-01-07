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
    enforce(PoW.length >= difficulty.length);
    
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

struct Difficulty
{
    /*
     * Difficulty sets minimum valid hash value.
     * 
     * Difficulty hash mask explanation:
     * 
     * |<- most significant  less significant ->
     * FF FF FF FF FF DE AD BE EF 00 00 00 00 00 00
     * ^^^^^^^^^^^^^^ ^^^^^^^^^^^
     * exponent = 5   mantissa = [0xEF, 0xBE, 0xAD, 0xDE]
     * 
     * Valid hash for this explanation is:
     * FF FF FF FF FF FF FE FE FE 11 11 11 00 00 00
     * 
     */
    
    ubyte exponent;
    ubyte[] mantissa;
}

bool isSatisfyDifficulty(inout PoW pow, inout Difficulty d) pure @nogc
{
    assert(pow.length >= d.exponent + d.mantissa.length);
    
    immutable PoWExpBorder = pow.length - d.exponent;
    
    // exponent part check
    foreach_reverse(pf; pow[PoWExpBorder..$])
        if(pf < 0xFF) return false;
    
    // mantissa part check
    foreach_reverse(i, m; d.mantissa)
        if(pow[PoWExpBorder-(d.mantissa.length-i)] < m) return false;
    
    return true;
}

unittest
{
    PoW p;
    p[60] = 0x01;
    p[61] = 0x00;
    p[62] = 0xFF;
    p[63] = 0xFF;
    
    Difficulty d1 = {exponent: 2, mantissa:[0x00, 0x00]};
    Difficulty d2 = {exponent: 2, mantissa:[0x01, 0x00]};
    Difficulty d3 = {exponent: 0, mantissa:[0x00, 0x00]};
    Difficulty d4 = {exponent: 0, mantissa:[0x00, 0x00, 0xFF, 0xFF]};
    Difficulty d5 = {exponent: 0, mantissa:[0x00, 0x00, 0xFF, 0xFF, 0xFF]};
    
    assert(isSatisfyDifficulty(p, d1));
    assert(isSatisfyDifficulty(p, d2));
    assert(isSatisfyDifficulty(p, d3));
    assert(isSatisfyDifficulty(p, d4));
    assert(!isSatisfyDifficulty(p, d5));
}
