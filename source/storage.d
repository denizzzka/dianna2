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
    key BLOB NOT NULL,
    value BLOB NOT NULL,
    signature BLOB NOT NULL,
EOS";

immutable string sqlCreateSchema =
`CREATE TABLE IF NOT EXISTS records (
`~sqlRecordFields~`
    blockNum INT NOT NULL,
    prevFilledBlockHash BLOB,
    proofOfWorkHash BLOB NOT NULL,
    proofOfWorkSalt BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS recordsAwaitingPublish (
`~sqlRecordFields~`
    blockNum INT,
    prevFilledBlockHash BLOB,
    proofOfWorkHash BLOB,
    proofOfWorkSalt BLOB
);

CREATE UNIQUE INDEX IF NOT EXISTS recordsAwaitingPublish_uniq
ON recordsAwaitingPublish(chainType, key, value, signature);

CREATE INDEX IF NOT EXISTS prev_block
ON records(prevFilledBlockHash);

CREATE TABLE IF NOT EXISTS blocks (
    hash BLOB NOT NULL,
    blockNum INT,
    difficultyExponent INT NOT NULL,
    difficultyMantissa BLOB,
    prevFilledBlockHash BLOB
);

CREATE UNIQUE INDEX IF NOT EXISTS block_num
ON blocks(hash);
`;

class Storage
{
    const string path;
    Database db;
    
    private Query
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
        db.execute(sqlCreateSchema);
        
        qInsertRec = db.query(
q"EOS
INSERT INTO records (
    version,
    chainType,
    key,
    value,
    signature,
    blockNum,
    prevFilledBlockHash,
    proofOfWorkHash,
    proofOfWorkSalt
)
VALUES (
    0,
    :chainType,
    :key,
    :value,
    :signature,
    :blockNum,
    :prevFilledBlockHash,
    :proofOfWorkHash,
    :proofOfWorkSalt
)
EOS"
        );
        
        qInsertRecAwaitingPublish = db.query("
            INSERT INTO recordsAwaitingPublish (
                version,
                chainType,
                key,
                value,
                signature
            )
            VALUES (
                0,
                :chainType,
                :key,
                :value,
                :signature
            )
        ");
        
        qSelectOldestRecsAwaitingPublish = db.query("
            SELECT
                key,
                value,
                signature
            FROM recordsAwaitingPublish
            WHERE version = 0
            AND chainType = :chainType
            AND blockNum IS NULL -- means that hash and other is not calculated
            ORDER BY rowid
            LIMIT :num
        ");
        
        qUpdateCalculatedPoW = db.query("
            UPDATE recordsAwaitingPublish SET
            
            blockNum = :blockNum,
            prevFilledBlockHash = :prevFilledBlockHash,
            proofOfWorkHash = :proofOfWorkHash,
            proofOfWorkSalt = :proofOfWorkSalt
                        
            WHERE chainType = :chainType
            AND key = :key
            AND value = :value
            AND signature = :signature
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
        qInsertRec.bind(":key", r.key);
        qInsertRec.bind(":value", r.value);
        qInsertRec.bind(":signature", r.signature);
        qInsertRec.bind(":blockNum", r.blockNum);
        qInsertRec.bind(":prevFilledBlockHash", r.prevFilledBlock);
        qInsertRec.bind(":proofOfWorkHash", r.proofOfWork.hash);
        qInsertRec.bind(":proofOfWorkSalt", r.proofOfWork.salt);
        
        qInsertRec.execute();
        assert(db.changes() == 1);
        qInsertRec.reset();
    }
    
    void addRecordAwaitingPoW(Record r)
    {
        alias q = qInsertRecAwaitingPublish;
        
        q.bind(":chainType", r.chainType);
        q.bind(":key", r.key);
        q.bind(":value", r.value);
        q.bind(":signature", r.signature);
        
        q.execute();
        assert(db.changes() == 1);
        q.reset();
    }
    
    shared (Record[]) getOldestRecordsAwaitingPoW(ChainType chainType, size_t num)
    {
        alias q = qSelectOldestRecsAwaitingPublish;
        
        q.bind(":chainType", chainType);
        q.bind(":num", num);
        
        q.execute();
        
        Record[] res;
        
        foreach(row; q)
        {
            Record r = {
                chainType: chainType,
                key: row["key"].as!(ubyte[]),
                value: row["value"].as!(ubyte[]),
                signature: to!Signature(row["signature"].as!(ubyte[]))
            };
            
            res ~= r;
        }
        
        q.reset();
        
        return cast(shared Record[]) res;
    }
    
    void setCalculatedPoW(Record r)
    {
        alias q = qUpdateCalculatedPoW;
        
        q.bind(":chainType", r.chainType);
        q.bind(":key", r.key);
        q.bind(":value", r.value);
        q.bind(":signature", r.signature);
        q.bind(":blockNum", r.blockNum);
        q.bind(":prevFilledBlockHash", r.prevFilledBlock);
        q.bind(":proofOfWorkHash", r.proofOfWork.hash);
        q.bind(":proofOfWorkSalt", r.proofOfWork.salt);
        
        q.execute();
        assert(db.changes() == 1);
        q.reset();
    }
}

unittest
{
    auto s = new Storage("_unittest.sqlite");
    
    Record r = {
            chainType: ChainType.Test,
            key:[0xDE, 0xEA, 0xBE, 0xEF],
            value:[0x11, 0x22, 0x33, 0x44]
        };
    
    s.Insert(r);
    
    s.purge;
}
