@safe

import std.datetime;
import std.conv;
import std.digest.sha;
import std.typecons;


enum ChainType
{
    Real,
    Test
}

alias RecordHash = Typedef!ubyte[10];
alias BlockHash = Typedef!ubyte[10];
alias Signature = Typedef!ubyte[10];
alias PoW = Typedef!ubyte[10];

struct Record
{
    ChainType chainType;
    ubyte[] key;
    ubyte[] value;
    Signature signature;
    uint blockNum;
    BlockHash prevFilledBlock;
    PoW proofOfWork;
    
    ubyte[] dumpPlainBinary() const
    {
        ubyte[] res;
        
        res ~= to!string(chainType);
        res ~= key ~ value;
        res ~= cast(ubyte[])signature;
        res ~= to!string(blockNum);
        res ~= cast(ubyte[])prevFilledBlock;
        res ~= cast(ubyte[])proofOfWork;
        
        return res;
    }
}

unittest
{
    Record r;
    auto d = r.dumpPlainBinary;
    assert(d.length >= 35);
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
    BlockHash res;
    
    foreach(r; records){}
    
    return res;
}
