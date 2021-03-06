@safe:

import storage;
import records;
import dnsvalue;
import generation;
import protobuf;

import core.time: Duration, dur;
import core.cpuid: threadsPerCPU;
import std.json;
debug(PoW) import std.stdio;


void createNewRecord(Storage s, in ChainType chainType, DNSValue dnsValue)
{
    Record r;
    
    r.chainType = chainType;
    r.payloadType = PayloadType.DNS;
    r.payload = dnsValue.serialize();
    r.hash = r.calcPayloadHash();
    
    s.addRecordAwaitingPoW(r);
}

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

void publishRecord(Storage s, ChainType chain)
{
    immutable _savepoint = "publishRecord";
    s.savepoint(_savepoint);
    
    const arr = s.getOldestRecordsAwaitingPublish(chain, true, 1);
    
    if(arr.length)
    {
        const r = arr[0];
        // TODO: publish record to the p2p network (TODO: create method) or rollback
        s.addRecord(r);
        s.deleteRecordAwaitingPublish(r.hash);
    }
    
    s.release(_savepoint);
}

JSONValue getDNSRecord(Storage s, ChainType chainType, string key) @trusted
{
    JSONValue j;
    bool avail;
    
    auto dnsRecords = followByChain(s, chainType, key);
    
    foreach_reverse(ref d; dnsRecords)
    {
        if(d.pb.keyValue.flags == RecordFlags.Announce)
        {
            avail = true;
            j = JSONValue();
        }
        
        if(d.pb.keyValue.flags == RecordFlags.Cancel)
        {
            avail = false;
            j = JSONValue();
        }
        
        if(avail)
        {
            j = d.toJSON;
        }
    }
    
    return j;
}

@trusted unittest
{
    import std.file: remove;
    
    auto s = new Storage("_unittest_work.sqlite");
    
    DNSValue dv;
    dv.key = "test key";
    dv.keyValue.payload = cast(ubyte[]) "test value";
    
    immutable path = "/tmp/_unittest_work_key.pem";
    ecdsa.createKeyPair(path);
    
    dv.sign(path);
    
    remove(path);
    
    s.createNewRecord(ChainType.Test, dv);
    
    debug(FastUnittest){} else // adding more records
    {
        s.createNewRecord([0x00, 0x01, 0x02]);
        s.createNewRecord([0x03, 0x04, 0x05]);
    }
    
    s.calcPowForNewRecords(ChainType.Test);
    s.publishRecord(ChainType.Test); // TODO: need to publish all records
    
    //s.writeInitialBlockHashSetting();
    
    //const j1 = s.getDNSRecord(ChainType.Test, "unavailable-domain");
    
    //import std.stdio;
    //writeln("j1=", j1.toPrettyString);
    
    s.purge;
}
