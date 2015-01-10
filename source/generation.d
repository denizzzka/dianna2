@trusted:

import records;
import core.time;
import std.concurrency;
import std.random: uniform;
debug(PoWt) import std.stdio; // PoWt == "PoW threads"


bool calcPowWithTimeout(
    immutable Record r,
    immutable Duration duration,
    immutable size_t threadsNum,
    out PoW pow
)
{
    Tid[] children;
    
    debug(PoWt) writeln("Start workers");
    foreach(i; 0..threadsNum)
        children ~= spawn(&worker, r);
    
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

private void worker(immutable Record r)
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

void benchmark()
{
    import std.stdio;
    import std.datetime;
    import core.cpuid: threadsPerCPU;
    
    
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
    
    writeln("Hashes per minute: ", 1.0 * hashes / sw.peek.seconds * 60);
    writeln("Elapsed time, minutes: ", 1.0 * sw.peek.seconds / 60);
}
