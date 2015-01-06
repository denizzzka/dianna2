@safe

import std.datetime;
import std.conv;

enum ChainType
{
    Real,
    Test
}

struct Record
{
    ChainType chainType;
    ubyte[] key;
    ubyte[] value;
}

immutable half_block_duration_hours = 12;

uint CalcLatestFilledBlockNum()
{
    uint hours = to!uint(Clock.currTime.toUnixTime / 3600);
    return hours / half_block_duration_hours - 2;
}

unittest
{
    assert(CalcLatestFilledBlockNum > 32800);
}
