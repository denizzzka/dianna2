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
    size_t freeThreads = threadsNum;
    
    Record[] records = s.getOldestRecordsAwaitingPoW(chainType, freeThreads);
    
    if(records.length == 0) return;
    
    freeThreads -= records.length;
    
    foreach(i; 0..records.length)
    {
        spawn(&worker, cast(shared Record) records[0]);
    }
    
    //s.setCalculatedPoW(_r);
}

private void worker(shared Record r) @trusted
{
    auto _r = cast(Record) r;
    
    immutable RecordHash hash = _r.calcHash;
    
    Difficulty smallDifficulty = {exponent: 0, mantissa:[0x88]};
    
    import std.stdio;
    writeln("thread started for record key=", _r.key);
    
    if(tryToCalcProofOfWork(hash, smallDifficulty, _r.proofOfWork))
    {
        writeln("solved!");
        send(ownerTid(), r);
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
    
    s.calcPowForNewRecords(ChainType.Test, 1);
    
    s.purge;
}
