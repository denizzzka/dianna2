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
ON recordsAwaitingPublish(chainType, key, value);

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
    key,
    value,
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
    :blockNum,
    :prevFilledBlockHash,
    :proofOfWorkHash,
    :proofOfWorkSalt
)
EOS"
        );
        
        qInsertRecAwaitingPublish = db.prepare("
            INSERT INTO recordsAwaitingPublish (
                version,
                chainType,
                key,
                value
            )
            VALUES (
                0,
                :chainType,
                :key,
                :value
            )
        ");
        
        qSelectOldestRecsAwaitingPublish = db.prepare("
            SELECT
                key,
                value
            FROM recordsAwaitingPublish
            WHERE version = 0
            AND chainType = :chainType
            AND blockNum IS NULL -- means that hash and other is not calculated
            ORDER BY rowid
            LIMIT :num
        ");
        
        qUpdateCalculatedPoW = db.prepare("
            UPDATE recordsAwaitingPublish SET
            
            blockNum = :blockNum,
            prevFilledBlockHash = :prevFilledBlockHash,
            proofOfWorkHash = :proofOfWorkHash,
            proofOfWorkSalt = :proofOfWorkSalt
                        
            WHERE chainType = :chainType
            AND key = :key
            AND value = :value
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
        qInsertRec.bind(":blockNum", r.blockNum);
        qInsertRec.bind(":prevFilledBlockHash", r.prevFilledBlock.getUbytes);
        qInsertRec.bind(":proofOfWorkHash", r.proofOfWork.hash);
        qInsertRec.bind(":proofOfWorkSalt", r.proofOfWork.salt);
        
        qInsertRec.execute();
        assert(db.changes() == 1);
        qInsertRec.reset();
    }
    
    void addRecordAwaitingPoW(ref Record r)
    {
        alias q = qInsertRecAwaitingPublish;
        
        q.bind(":chainType", r.chainType);
        q.bind(":key", r.key);
        q.bind(":value", r.value);
        
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
                key: row["key"].as!(ubyte[]),
                value: row["value"].as!(ubyte[])
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
        q.bind(":key", r.key);
        q.bind(":value", r.value);
        q.bind(":blockNum", r.blockNum);
        q.bind(":prevFilledBlockHash", r.prevFilledBlock.getUbytes);
        q.bind(":proofOfWorkHash", r.proofOfWork.hash);
        q.bind(":proofOfWorkSalt", r.proofOfWork.salt);
        
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
        key: [0x6b, 0x6b, 0x6b, 0x6b],
        value: [0x76, 0x76, 0x76, 0x76]
    };
    
    s.Insert(r);
    
    s.addRecordAwaitingPoW(r);
    
    r.proofOfWork.hash[0..3] = [0x48, 0x48, 0x48];
    s.setCalculatedPoW(r);
    
    s.purge;
}
