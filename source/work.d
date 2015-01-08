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

void calcPowForNewRecords(Storage s, ChainType chainType, size_t threadsNum) @trusted
{
    size_t currThreads = 0;
    shared Storage _s = cast(shared Storage) s;
    
    for(;;)
    {
        Record[] records = s.getOldestRecordsAwaitingPoW(chainType, 1);
        
        if(records.length == 0) break;
        
        assert(records.length == 1);
        
        spawn(&worker, _s, cast(shared Record) records[0]);
    }    
}

private void worker(shared Storage s, shared Record r)
{
    //immutable RecordHash hash = r.calcHash;
    
    Difficulty difficulty;
    PoW pow;
    
    //if(tryToCalcProofOfWork(hash, difficulty, pow))
        //s.setCalculatedPoW(r);
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
