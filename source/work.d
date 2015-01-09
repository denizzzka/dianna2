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
        
        import std.stdio;
        writeln("records.length=", records.length);
        
        if(records.length == 0) return;
        assert(records.length == 1);
        
        calcPowForRecord(records[0], threadsNum);
        
        s.setCalculatedPoW(records[0]);
    } while(records.length == 1);
    
}

void calcPowForRecord(ref Record r, in size_t threadsNum) @trusted
{
    Tid[] children;
    
    // Start workers
    foreach(i; 0..threadsNum)
    {
        Record* _r = new Record;
        *_r = r;
        
        children ~= spawn(&worker, cast(shared Record*) _r);
    }
    
    // Wait for any children why solved PoW
    r = cast(Record) *receiveOnly!(shared(records.Record)*);
    
    // PoW found, stop all threads
    foreach(ref c; children)
        send(c, true);
    
    import std.stdio;
    writeln("Wait for children termination");
    // Wait for children termination
    foreach(i; 0..children.length)
    {
        receive(
            (ubyte){}
        );
        
        // mbox also can contain other "solved" messages from
        // any another lucky threads - need to receive it too
        Duration dur;
        receiveTimeout(dur, (shared(records.Record)*){});
        
        writeln("terminated, i=", i);
    }
}

private void worker(shared Record* r) @trusted
{
    auto _r = cast(Record*) r;
    
    Difficulty smallDifficulty = {exponent: 0, mantissa:[0x33]};
    
    import std.stdio;
    writeln("thread started for record key=", _r.key);
    
    for(auto i = 1;; i++)
    {
        // Generate random salt
        ubyte[8] salt;
        foreach(ref e; salt)
            e = uniform!ubyte;
        
        // "close this thread" message received?
        Duration dur;
        if(receiveTimeout(dur, (bool){}))
            break;
        
        if(tryToCalcProofOfWork(_r.calcHash, smallDifficulty, salt, _r.proofOfWork))
        {
            writeln("solved! i=", i, " proofOfWork=", _r.proofOfWork);
            
            send(ownerTid(), r);
            break;
        }
    }
    
    // message what means "child is stopped"
    send(ownerTid(), cast(ubyte) 0xED);
}

unittest
{
    auto s = new Storage("_unittest_work.sqlite");
    
    s.createNewRecord([0x00, 0x01, 0x02], [0x11, 0x22, 0x33]);
    s.createNewRecord([0x01, 0x01, 0x02], [0x11, 0x22, 0x33]);
    s.createNewRecord([0x02, 0x01, 0x02], [0x11, 0x22, 0x33]);
    
    auto r = s.getOldestRecordsAwaitingPoW(ChainType.Test, 2);
    assert(r.length == 2);
    
    s.calcPowForNewRecords(ChainType.Test, 3);
    
    s.purge;
}
