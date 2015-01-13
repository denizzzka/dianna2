@safe:

import storage;
import records;
import generation;
import core.time: Duration, dur;
import core.cpuid: threadsPerCPU;
debug(PoW) import std.stdio;


void createNewRecord(Storage s, ubyte[] payload)
{
    Record r;
    
    r.chainType = ChainType.Test;
    r.payloadType = PayloadType.Test;
    r.payload = payload;
    r.hash = r.calcPayloadHash();
    
    s.addRecordAwaitingPoW(r);
}

private void calcPowForRecord(ref Record r) @trusted
{
    immutable threads = threadsPerCPU;
    bool isFound;
    
    do
    {
        immutable _r = cast(immutable Record) r;
        immutable f = _r.getFullRecordHashSource();
        
        isFound = calcPowWithTimeout(f, _r.difficulty, dur!"seconds"(10), threads, r.proofOfWork);
    }
    while(!isFound);
}

void calcPowForNewRecords(Storage s, ChainType chainType) @trusted
{
    Record[] records;
    
    do
    {
        records = s.getOldestRecordsAwaitingPublish(chainType, false, 1);
        
        debug(PoW) writeln("Got ", records.length, " record(s) awaiting PoW");
        
        if(records.length == 0) return;
        assert(records.length == 1);
        
        auto r = &records[0];
        r.difficulty = 0xDFFFFFFFFFFFFFFF;
        
        calcPowForRecord(*r);
        
        s.setCalculatedPoW(*r);
    }
    while(records.length > 0);
}

unittest
{
    auto s = new Storage("_unittest_work.sqlite");
    
    s.createNewRecord([0x00, 0x01, 0x02]);
    s.createNewRecord([0x01, 0x01, 0x02]);
    s.createNewRecord([0x02, 0x01, 0x02]);
    
    s.calcPowForNewRecords(ChainType.Test);
    
    s.purge;
}
