@safe:

import storage;
import records;
import std.concurrency;
import core.atomic: atomicOp;


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
    Record[] records = s.getOldestRecordsAwaitingPoW(chainType, 1);
    
    if(records.length == 0) return;
    assert(records.length == 1);
    
    foreach(i; 0..threadsNum)
    {
        Record* r = new Record;
        *r = records[0];
        
        spawn(&worker, cast(shared Record*) r);
    }
    
    //s.setCalculatedPoW(_r);
}

private void worker(shared Record* r) @trusted
{
    auto _r = cast(Record*) r;
    
    Difficulty smallDifficulty = {exponent: 0, mantissa:[0x88]};
    
    import std.stdio;
    writeln("thread started for record key=", _r.key);
    
    foreach(i; 0..99)
    {
        if(tryToCalcProofOfWork(_r.calcHash, smallDifficulty, _r.proofOfWork))
        {
            writeln("solved! i=", i, " proofOfWork=", _r.proofOfWork);
            send(ownerTid(), r);
            return;
        }
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
    
    s.calcPowForNewRecords(ChainType.Test, 3);
    
    s.purge;
}
