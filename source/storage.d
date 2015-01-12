@trusted:

import records;
import d2sqlite3;

import std.exception: enforce;
import std.process: environment;
import std.file;
import core.stdc.errno;
import std.conv: to;


immutable string sqlRecordFields = q"EOS
    version INT NOT NULL,
    chainType INT NOT NULL, -- 0 = real chain, 1 = test chain
    payloadType INT NOT NULL,
    payload BLOB NOT NULL,
EOS";

immutable string sqlCreateSchema =
`CREATE TABLE IF NOT EXISTS records (
`~sqlRecordFields~`
    hash BLOB NOT NULL,
    blockNum INT NOT NULL,
    prevFilledBlockHash BLOB,
    proofOfWork BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS recordsAwaitingPublish (
`~sqlRecordFields~`
    hash BLOB,
    blockNum INT,
    prevFilledBlockHash BLOB,
    proofOfWork BLOB
);

CREATE UNIQUE INDEX IF NOT EXISTS recordsAwaitingPublish_uniq
ON recordsAwaitingPublish(chainType, payloadType, payload);

CREATE INDEX IF NOT EXISTS prev_block
ON records(prevFilledBlockHash);

CREATE TABLE IF NOT EXISTS blocks (
    hash BLOB NOT NULL,
    blockNum INT,
    difficulty INT NOT NULL,
    prevFilledBlockHash BLOB
);

CREATE UNIQUE INDEX IF NOT EXISTS block_num
ON blocks(hash);
`;

class Storage
{
    const string path;
    Database db;
    
    private Statement
        qInsertRec,
        qInsertRecAwaitingPublish,
        qSelectOldestRecsAwaitingPublish,
        qUpdateCalculatedPoW;
    
    this(string filename)
    {
        enforce(sqlite3_threadsafe(), "SQLite3 is not threadsafe");
        
        string home = environment["HOME"];
        string appdir = home~"/.dianna2";
        path = appdir~"/"~filename;
        
        try
            mkdir(appdir);
        catch(FileException e)
            if(e.errno != EEXIST) throw e;
        
        db = Database(path);
        db.run(sqlCreateSchema);
        
        qInsertRec = db.prepare(
q"EOS
INSERT INTO records (
    version,
    chainType,
    payloadType,
    payload,
    hash,
    blockNum,
    prevFilledBlockHash,
    proofOfWork
)
VALUES (
    0,
    :chainType,
    :payloadType,
    :payload,
    :hash,
    :blockNum,
    :prevFilledBlockHash,
    :proofOfWork
)
EOS"
        );
        
        qInsertRecAwaitingPublish = db.prepare("
            INSERT INTO recordsAwaitingPublish (
                version,
                chainType,
                payloadType,
                payload
            )
            VALUES (
                0,
                :chainType,
                :payloadType,
                :payload
            )
        ");
        
        qSelectOldestRecsAwaitingPublish = db.prepare("
            SELECT
                payloadType,
                payload
                
            FROM recordsAwaitingPublish
            
            WHERE version = 0
            AND chainType = :chainType
            AND blockNum IS NULL -- means that hash and other is not calculated
            ORDER BY rowid
            LIMIT :num
        ");
        
        qUpdateCalculatedPoW = db.prepare("
            UPDATE recordsAwaitingPublish SET
            
            hash = :hash,
            blockNum = :blockNum,
            prevFilledBlockHash = :prevFilledBlockHash,
            proofOfWork = :proofOfWork
                        
            WHERE chainType = :chainType
            AND payloadType = :payloadType
            AND payload = :payload
        ");
    }
    
    version(unittest)
    void purge()
    {
        remove(path);
    }
    
    void Insert(Record r)
    {
        qInsertRec.bind(":chainType", r.chainType);
        qInsertRec.bind(":payloadType", r.payloadType);
        qInsertRec.bind(":payload", r.payload);
        qInsertRec.bind(":hash", r.hash.getUbytes);
        qInsertRec.bind(":blockNum", r.blockNum);
        qInsertRec.bind(":prevFilledBlockHash", r.prevFilledBlock.getUbytes);
        qInsertRec.bind(":proofOfWork", r.proofOfWork.getUbytes);
        
        qInsertRec.execute();
        assert(db.changes() == 1);
        qInsertRec.reset();
    }
    
    void addRecordAwaitingPoW(ref Record r)
    {
        alias q = qInsertRecAwaitingPublish;
        
        q.bind(":chainType", r.chainType);
        q.bind(":payloadType", r.payloadType);
        q.bind(":payload", r.payload);
        
        q.execute();
        assert(db.changes() == 1);
        q.reset();
    }
    
    Record[] getOldestRecordsAwaitingPoW(ChainType chainType, size_t num)
    {
        alias q = qSelectOldestRecsAwaitingPublish;
        
        q.bind(":chainType", chainType);
        q.bind(":num", num);
        
        auto queryRes = q.execute();
        
        Record[] res;
        
        foreach(row; queryRes)
        {
            Record r = {
                chainType: chainType,
                payloadType: row["payloadType"].as!PayloadType,
                payload: row["payload"].as!(ubyte[])
            };
            
            res ~= r;
        }
        
        q.reset();
        
        return res;
    }
    
    void setCalculatedPoW(in Record r)
    {
        alias q = qUpdateCalculatedPoW;
        
        q.bind(":chainType", r.chainType);
        q.bind(":payloadType", r.payloadType);
        q.bind(":payload", r.payload);
        q.bind(":hash", r.hash.getUbytes);
        q.bind(":blockNum", r.blockNum);
        q.bind(":prevFilledBlockHash", r.prevFilledBlock.getUbytes);
        q.bind(":proofOfWork", r.proofOfWork.getUbytes);
        
        q.execute();
        assert(db.changes() == 1);
        q.reset();
    }
}

unittest
{
    auto s = new Storage("_unittest_storage.sqlite");
    
    Record r = {
        chainType: ChainType.Test,
        payloadType: PayloadType.Test,
        payload: [0x76, 0x76, 0x76, 0x76]
    };
    
    s.Insert(r);
    
    s.addRecordAwaitingPoW(r);
    
    r.proofOfWork.hash[0..3] = [0x48, 0x48, 0x48];
    s.setCalculatedPoW(r);
    
    s.purge;
}
