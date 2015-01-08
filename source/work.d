@safe:

import storage;
import records;


void storeRecord(ubyte[] key, ubyte[] value)
{
    Record record;
    
    record.chainType = ChainType.Test;
    record.key = key;
    record.value = value;
}
