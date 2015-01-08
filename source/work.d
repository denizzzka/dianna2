@safe:

import storage;
import records;


void createNewRecord(Storage s, ubyte[] key, ubyte[] value)
{
    Record r;
    
    r.chainType = ChainType.Test;
    r.key = key;
    r.value = value;
    r.signature = new ubyte[10];

    s.addRecordAwaitingPoW(r);
}

unittest
{
    auto s = new Storage("_unittest.sqlite");
    
    s.createNewRecord([0x00, 0x01, 0x02], [0x11, 0x22, 0x33]);
    
    s.purge;
}
