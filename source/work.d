@safe:

import storage;
import records;
import std.concurrency;
import core.time: Duration;
import std.random;
debug(PoWt) import std.stdio; // PoWt is "PoW threads"


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
        
        debug(PoWt) writeln("Got ", records.length, " record(s) awaiting PoW");
        
        if(records.length == 0) return;
        assert(records.length == 1);
        
        calcPowForRecord(records[0], threadsNum);
        
        s.setCalculatedPoW(records[0]);
    } while(records.length == 1);
    
}

void calcPowForRecord(ref Record r, in size_t threadsNum) @trusted
{
    Tid[] children;
    
    debug(PoWt) writeln("Start workers");
    foreach(i; 0..threadsNum)
    {
        Record* _r = new Record;
        *_r = r;
        
        children ~= spawn(&worker, cast(shared Record*) _r);
    }
    
    debug(PoWt) writeln("Wait for any child why solved PoW");
    r = cast(Record) *receiveOnly!(shared(records.Record)*);
    
    debug(PoWt) writeln("PoW found, sending 'stop' for all threads");
    foreach(ref c; children)
        send(c, true);
    
    debug(PoWt) writeln("Wait for children termination");
    foreach(i; 0..children.length)
    {
        receive(
            (ubyte){}
        );
        
        /*
         * mbox can also contain other "solved" messages from any
         * another lucky threads - it is need to receive it too
         */
        Duration dur;
        receiveTimeout(dur, (shared(records.Record)*){});
        
        debug(PoWt) writeln("Child ", i, " terminated");
    }
}

private void worker(shared Record* r) @trusted
{
    auto _r = cast(Record*) r;
    
    debug(PoWt) auto id = "(no id)";
    debug(PoWt) writeln("Worker ", id, " thread started for Record.key=", _r.key);
    
    for(auto i = 1;; i++)
    {
        debug(PoWt) writeln("Worker ", id, " iteration: ", i);
        
        // Generate random salt
        foreach(ref e; _r.proofOfWork.salt)
            e = uniform!ubyte;
        
        // "close this thread" message received?
        Duration dur;
        if(receiveTimeout(dur, (bool){}))
            break;
        
        _r.proofOfWork.hash = calcPoWHash(_r.calcHash, _r.proofOfWork.salt);
        
        if(isSatisfyDifficulty(_r.proofOfWork.hash, 0xDFFFFFFFFFFFFFFF))
        {
            debug(PoWt) writeln("PoW solved, worker ", id, ", proofOfWork=", _r.proofOfWork);
            
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

/*
void benchmark() @trusted
{
    import std.stdio;
    import std.datetime;
    import core.cpuid;
    
    immutable size_t threads = threadsPerCPU();
    StopWatch sw;    
    Record r;
    immutable hashes = 6;
    
    writeln("Starting benchmarking");
    writeln("Hashes: ", hashes, ", threads: ", threads);
    
    sw.start();
    
    foreach(i; 1..hashes)
        calcPowForRecord(r, threads);
    
    sw.stop();
    
    writeln("Hashes per second: ", (cast(float) hashes) / sw.peek.seconds);
    writeln("Elapsed time, seconds: ", sw.peek.seconds);
}
*/
