
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
