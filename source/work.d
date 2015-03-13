@safe:

import storage;
import records;
import dnsvalue;
import generation;
import protobuf;

import vibe.data.json;

import core.time: Duration, dur;
import core.cpuid: threadsPerCPU;
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

string getDNSRecord(Storage s, ChainType chainType, string key) @trusted
{
    //const b = s.findLatestHonestBlock(1_000_000_000);
    
    auto dnsRecords = followByChain(s, chainType, key);
    
    Json j;
    bool avail;
    foreach_reverse(ref d; dnsRecords)
    {
        if(d.pb.keyValue.flags == RecordFlags.Announce)
        {
            avail = true;
            j = Json.emptyObject;
        }
        
        if(d.pb.keyValue.flags == RecordFlags.Cancel)
        {
            avail = false;
            j = Json.emptyObject;
        }
        
        if(avail)
        {
            //j ~=
        }
    }
    
    return key;
}

@trusted unittest
{
    import std.file: remove;
    
    auto s = new Storage("_unittest_work.sqlite");
    
    s.createNewRecord([0x00, 0x01, 0x02]);
    s.createNewRecord([0x01, 0x01, 0x02]);
    s.createNewRecord([0x02, 0x01, 0x02]);
    
    s.calcPowForNewRecords(ChainType.Test);
    
    DNSValue dv;
    
    dv.key = "test key";
    dv.keyValue.payload = cast(ubyte[]) "test value";
    
    immutable path = "/tmp/_unittest_work_key.pem";
    ecdsa.createKeyPair(path);
    
    dv.sign(path);
    
    remove(path);
    
    s.createNewRecord(ChainType.Test, dv);
    s.calcPowForNewRecords(ChainType.Test);
    //s.writeInitialBlockHashSetting();
    
    s.purge;
}
