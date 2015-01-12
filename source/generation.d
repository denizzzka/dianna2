@trusted:

import records;
import core.time;
import std.concurrency;
debug(PoWt) import std.stdio; // PoWt == "PoW threads"


bool calcPowWithTimeout(
    immutable RecordHash recordHash,
    immutable Difficulty difficulty,
    immutable Duration duration,
    immutable size_t threadsNum,
    out PoW pow
)
{
    Tid[] children;
    
    debug(PoWt) writeln("Hash: ", recordHash);
    debug(PoWt) writefln("Difficulty: %X", difficulty);
    debug(PoWt) writeln("Start workers");
    foreach(i; 0..threadsNum)
        children ~= spawn(&worker, recordHash, difficulty);
    
    debug(PoWt) writeln("Wait for any child why solved PoW");
    bool isFound = receiveTimeout(duration,
        (PoW _pow){ pow = _pow; }
    );
    
    debug(PoWt) writeln("Sending 'stop' for all threads");
    foreach(ref c; children)
        send(c, true);
    
    debug(PoWt) writeln("Wait for children termination");
    foreach(i; 0..children.length)
    {
        receive(
            (ubyte){}
        );
        
        /*
         * mbox also can contain other "solved" messages from any
         * another lucky thread - it is need to receive it too
         */
        receiveTimeout(dur!"seconds"(0),
            (PoW _pow){ pow = _pow; isFound = true; }
        );
        
        debug(PoWt) writeln("Child ", i, " terminated");
    }
    
    return isFound;
}

private void worker(immutable RecordHash rHash, immutable Difficulty difficulty)
{
    debug(PoWt) auto id = "(no id)";
    debug(PoWt) writeln("Worker ", id, " thread started for record hash ", rHash);
    
    for(auto i = 1;; i++)
    {
        debug(PoWt) writeln("Worker ", id, " iteration: ", i);
        
        // "close this thread" message received?
        Duration dur;
        if(receiveTimeout(dur, (bool){}))
            break;
        
        PoW pow;
        pow.fillSalt();
        
        pow.hash = calcPoWHash(rHash, pow.salt);
        
        if(isSatisfyDifficulty(pow.hash, difficulty))
        {
            debug(PoWt) writeln("PoW solved, worker ", id, ", proofOfWork=", pow);
            
            send(ownerTid(), pow);
            break;
        }
    }
    
    // message what means "child is stopped"
    send(ownerTid(), cast(ubyte) 0xED);
}

void benchmark()
{
    import std.stdio;
    import std.datetime: StopWatch;
    import core.cpuid: threadsPerCPU;
    
    
    immutable threads = threadsPerCPU();
    immutable hashesPerThread = 10;    
    immutable hashes = hashesPerThread * threads;
    
    StopWatch sw;
    
    writeln("Starting benchmarking");
    writeln("Hashes: ", hashes, ", threads: ", threads);
    
    immutable Record r;
    immutable RecordHash h = r.calcHash();
    
    sw.start();
    
    foreach(n; 1..hashesPerThread)
    {
        PoW pow;
        
        // Any timeout is usable here
        calcPowWithTimeout(h, 0, dur!"usecs"(0), threads, pow);
    }
    
    sw.stop();
    
    writeln("Hashes per minute: ", 1.0 * hashes / sw.peek.seconds * 60);
    writeln("Elapsed time, minutes: ", 1.0 * sw.peek.seconds / 60);
}
