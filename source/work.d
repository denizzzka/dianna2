@safe:

import storage;
import records;
import std.concurrency;


void createNewRecord(Storage s, ubyte[] key, ubyte[] value)
{
    Record r;
    
    r.chainType = ChainType.Test;
    r.key = key;
    r.value = value;
    r.signature = new ubyte[10];

    s.addRecordAwaitingPoW(r);
}

void calcPowForNewRecords(Storage s, ChainType chainType, size_t threadsNum)
{
    Record[] records = s.getOldestRecordsAwaitingPoW(chainType, threadsNum);
    
    if(records.length == 0) return;
    
    void worker(Record r)
    {
        immutable RecordHash hash = r.calcHash;
        
        Difficulty difficulty;
        PoW pow;
        
        calcProofOfWork(hash, difficulty, pow);
    }
}

unittest
{
    auto s = new Storage("_unittest.sqlite");
    
    s.createNewRecord([0x00, 0x01, 0x02], [0x11, 0x22, 0x33]);
    s.createNewRecord([0x01, 0x01, 0x02], [0x11, 0x22, 0x33]);
    s.createNewRecord([0x02, 0x01, 0x02], [0x11, 0x22, 0x33]);
    
    auto r = s.getOldestRecordsAwaitingPoW(ChainType.Test, 2);
    assert(r.length == 2);
    
    s.purge;
}
