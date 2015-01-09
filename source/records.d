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

struct PoW
{
    alias Hash = ubyte[32];
    alias Salt = ubyte[8];
    
    Hash hash;
    Salt salt;
}

ulong extractDifficulty(in PoW.Hash h) pure @nogc
{
    immutable offset = h.length - ulong.sizeof;
    
    ubyte[ulong.sizeof] arr = h[offset..offset + ulong.sizeof];
    
    return ulong.max - littleEndianToNative!ulong(arr);
}

unittest
{
    PoW pow;
    pow.hash[24] = 1;
    
    assert(pow.hash.extractDifficulty() == ulong.max - 1);
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
        res ~= difficulty.exponent;
        res ~= difficulty.mantissa;
        
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
    inout ref Difficulty difficulty,
    inout PoW.Salt salt,
    out PoW pow
) pure
{
    enforce(pow.hash.length >= difficulty.length);
    
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
    
    this(this)
    {
        mantissa = mantissa.dup;
    }
}

bool isSatisfyDifficulty(inout typeof(PoW.hash) pow, inout ref Difficulty d) pure @nogc
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
    p.hash[28] = 0x01;
    p.hash[29] = 0x00;
    p.hash[30] = 0xFF;
    p.hash[31] = 0xFF;
    
    Difficulty d1 = {exponent: 2, mantissa:[0x00, 0x00]};
    Difficulty d2 = {exponent: 2, mantissa:[0x01, 0x00]};
    Difficulty d3 = {exponent: 0, mantissa:[0x00, 0x00]};
    Difficulty d4 = {exponent: 0, mantissa:[0x00, 0x00, 0xFF, 0xFF]};
    Difficulty d5 = {exponent: 0, mantissa:[0x00, 0x00, 0xFF, 0xFF, 0xFF]};
    
    assert(isSatisfyDifficulty(p.hash, d1));
    assert(isSatisfyDifficulty(p.hash, d2));
    assert(isSatisfyDifficulty(p.hash, d3));
    assert(isSatisfyDifficulty(p.hash, d4));
    assert(!isSatisfyDifficulty(p.hash, d5));
    
    Record[10] rec;
    auto hash = calcBlockHash(rec);
    
    PoW proof;
    Difficulty smallDifficulty = {exponent: 0, mantissa:[0x88]};
    
    ubyte[8] salt;
    do{
        genSalt(salt);
    }
    while(
        !tryToCalcProofOfWork(hash, smallDifficulty, salt, proof)
    );
    
    assert(isValidProofOfWork(hash, proof));
    
    BlockHash zeroHash;
    assert(hash != zeroHash);
    assert(!isValidProofOfWork(zeroHash, proof));
}
