@safe:

import storage;
import records;


void createNewRecord(ubyte[] key, ubyte[] value)
{
    Record r;
    
    r.chainType = ChainType.Test;
    r.key = key;
    r.value = value;
    r.signature = new ubyte[10];
}

unittest
{
    import std.conv;
    
    auto s = new Storage("_unittest.sqlite");
    
    createNewRecord([0x00, 0x01, 0x02], [0x00, 0x01, 0x02]);
    
    s.purge;
}
