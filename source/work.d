@safe:

import storage;
import records;
import std.concurrency;
import core.time: Duration, dur;
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
        
        records[0].difficulty = 0xDFFFFFFFFFFFFFFF;
        calcPowForRecord(records[0], threadsNum);
        
        s.setCalculatedPoW(records[0]);
    }
    while(records.length > 0);
}

void calcPowForRecord(ref Record r, inout size_t threadsNum) @trusted
{
    bool isFound;
    
    do
    {
        immutable _r = cast(immutable Record) r;
        
        isFound = calcPowWithTimeout(_r, dur!"seconds"(10), threadsNum, r.proofOfWork);
    }
    while(!isFound);
}

bool calcPowWithTimeout(
    immutable Record r,
    immutable Duration duration,
    immutable size_t threadsNum,
    out PoW pow
) @trusted
{
    Tid[] children;
    
    debug(PoWt) writeln("Start workers");
    foreach(i; 0..threadsNum)
        children ~= spawn(&worker, r);
    
    debug(PoWt) writeln("Wait for any child why solved PoW");
    immutable isFound = receiveTimeout(duration,
        (PoW _pow){ pow = _pow; }
    );
    
    debug(PoWt) writeln("PoW is "~(isFound?"":"not ")~"found, sending 'stop' for all threads");
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
        receiveTimeout(dur!"seconds"(0), (records.PoW){});
        
        debug(PoWt) writeln("Child ", i, " terminated");
    }
    
    return isFound;
}

private void worker(immutable Record r) @trusted
{
    debug(PoWt) auto id = "(no id)";
    debug(PoWt) writeln("Worker ", id, " thread started for Record.key=", r.key);
    
    for(auto i = 1;; i++)
    {
        debug(PoWt) writeln("Worker ", id, " iteration: ", i);
        
        // "close this thread" message received?
        Duration dur;
        if(receiveTimeout(dur, (bool){}))
            break;
        
        // Generate random salt
        PoW pow;
        foreach(ref e; pow.salt)
            e = uniform!ubyte;
        
        pow.hash = calcPoWHash(r.calcHash, pow.salt);
        
        if(isSatisfyDifficulty(pow.hash, r.difficulty))
        {
            debug(PoWt) writeln("PoW solved, worker ", id, ", proofOfWork=", pow);
            
            send(ownerTid(), pow);
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
    
    benchmark();
}

void benchmark() @trusted
{
    import std.stdio;
    import std.datetime;
    import core.cpuid;
    import std.random;
    
    
    immutable threads = threadsPerCPU();
    immutable hashesPerThread = 10;    
    immutable hashes = hashesPerThread * threads;
    
    StopWatch sw;
    
    writeln("Starting benchmarking");
    writeln("Hashes: ", hashes, ", threads: ", threads);
    
    sw.start();
    
    foreach(n; 1..hashesPerThread)
    {
        immutable Record r;
        PoW pow;
        
        calcPowWithTimeout(r, dur!"days"(365*10), threads, pow);
    }
    
    sw.stop();
    
    writeln("Hashes per minute: ", (cast(float) hashes) / sw.peek.seconds * 60);
    writeln("Elapsed time, minutes: ", cast(float) sw.peek.seconds / 60);
}
