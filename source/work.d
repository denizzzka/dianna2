@safe:

import storage;
import records;
import std.concurrency;
import core.time: Duration;
import std.random;


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
    Record[] records;
    
    do
    {
        records = s.getOldestRecordsAwaitingPoW(chainType, 1);
        
        if(records.length == 0) return;
        assert(records.length == 1);
        
        calcPowForRecord(records[0], threadsNum);
        
        // TODO: save PoW to DB
        s.setCalculatedPoW(records[0]);
    } while(records.length == 1);
    
}

void calcPowForRecord(ref Record r, size_t threadsNum) @trusted
{
    Tid[] children;
    
    foreach(i; 0..threadsNum)
    {
        Record* _r = new Record;
        *_r = r;
        
        children ~= spawn(&worker, cast(shared Record*) _r);
    }
        
    receive(
        (bool)
        {
            // PoW found, stop all threads
            import std.stdio;
            writeln("stop all threads");
            
            foreach(ref c; children)
                send(c, true);
        }
    );
}

private void worker(shared Record* r) @trusted
{
    auto _r = cast(Record*) r;
    
    Difficulty smallDifficulty = {exponent: 0, mantissa:[0x88]};
    
    import std.stdio;
    writeln("thread started for record key=", _r.key);
    
    foreach(i; 0..100)
    {
        ubyte[8] salt;
        foreach(ref e; salt)
            e = uniform!ubyte;
        
        Duration dur;
        receiveTimeout(dur,
            (bool){ return; } // "close this thread" message received
        );
        
        if(tryToCalcProofOfWork(_r.calcHash, smallDifficulty, salt, _r.proofOfWork))
        {
            writeln("solved! i=", i, " proofOfWork=", _r.proofOfWork);
            
            send(ownerTid(), true);
            return;
        }
    }
    
    send(ownerTid(), false);
}

unittest
{
    auto s = new Storage("_unittest_work.sqlite");
    
    s.createNewRecord([0x00, 0x01, 0x02], [0x11, 0x22, 0x33]);
    s.createNewRecord([0x01, 0x01, 0x02], [0x11, 0x22, 0x33]);
    s.createNewRecord([0x02, 0x01, 0x02], [0x11, 0x22, 0x33]);
    
    auto r = s.getOldestRecordsAwaitingPoW(ChainType.Test, 2);
    assert(r.length == 2);
    
    //s.calcPowForNewRecords(ChainType.Test, 3);
    
    s.purge;
}
