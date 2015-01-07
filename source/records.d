@safe:

import std.datetime;
import std.conv;
import std.digest.sha;
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

bool calcProofOfWork(
    inout SHA1_hash from,
    inout Difficulty difficulty,
    size_t iterations,
    out PoW pow
) pure
{
    enforce(pow.length >= difficulty.length);
    
    ubyte[8] salt;
        
    foreach(i; 0..iterations)
    {
        genSalt(salt);
        calcScrypt(pow, from, salt, 65536, 64, 1);
        
        if(isSatisfyDifficulty(pow, difficulty))
            return true;
    }
    
    return false;
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
     * Valid hash sample for this explanation:
     * FF FF FF FF FF FF FE FE FE 11 11 11 00 00 00
     * 
     */
    
    ubyte exponent;
    ubyte[] mantissa;
    
    size_t length() const pure
    {
        return exponent + mantissa.length;
    }
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
    
    Record[10] rec;
    auto hash = calcBlockHash(rec);
    
    PoW proof;
    Difficulty smallDifficulty = {exponent: 0, mantissa:[0x88]};
    calcProofOfWork(hash, smallDifficulty, 1, proof);
}
