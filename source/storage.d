@trusted:

import records;
import d2sqlite3;

import std.exception: enforce;
import std.process: environment;
import std.file;
import core.stdc.errno;
import std.conv: to;
import std.digest.sha;


immutable string sqlRecordFields = q"EOS
    chainType INT NOT NULL, -- 0 = real chain, 1 = test chain
    payloadType INT NOT NULL,
    payload BLOB NOT NULL,
    hash BLOB NOT NULL,
EOS";

immutable string sqlCreateSchema =
`CREATE TABLE IF NOT EXISTS records (
`~sqlRecordFields~`
    version INT NOT NULL,
    blockNum INT NOT NULL,
    prevFilledBlockHash BLOB,
    difficulty INT NOT NULL,
    proofOfWork BLOB NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS records_uniq
ON records(proofOfWork);

CREATE INDEX IF NOT EXISTS prev_block
ON records(prevFilledBlockHash);

CREATE TABLE IF NOT EXISTS recordsAwaitingPublish (
`~sqlRecordFields~`
    blockNum INT,
    prevFilledBlockHash BLOB,
    proofOfWork BLOB
);

CREATE UNIQUE INDEX IF NOT EXISTS recordsAwaitingPublish_uniq
ON recordsAwaitingPublish(hash);

CREATE TABLE IF NOT EXISTS blocks (
    blockHash BLOB NOT NULL,
    blockNum INT NOT NULL,
    difficulty INT NOT NULL,
    recordsNum INT NOT NULL,
    prevFilledBlockHash BLOB INT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS blocks_uniq
ON blocks(blockHash);

CREATE TABLE IF NOT EXISTS blocksContents (
    blockHash BLOB NOT NULL,
    proofOfWork BLOB NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS blocksContents_uniq
ON blocksContents(blockHash, proofOfWork);

CREATE TABLE IF NOT EXISTS AffectedRecords (
    blockNum INT NOT NULL,
    proofOfWork BLOB NOT NULL,
    prevFilledBlockHash BLOB NOT NULL,
    difficulty INT NOT NULL
);

DELETE FROM AffectedRecords;

CREATE TABLE IF NOT EXISTS NewBlocks (
    blockNum INT NOT NULL,
    blockHash BLOB NOT NULL,
    recordsNum INT NOT NULL,
    prevFilledBlockHash BLOB NOT NULL,
    difficulty INT NOT NULL
);

DELETE FROM NewBlocks;

CREATE TRIGGER IF NOT EXISTS blocksFilling
AFTER INSERT ON records FOR EACH ROW
BEGIN
    
    INSERT INTO AffectedRecords(blockNum, proofOfWork, prevFilledBlockHash, difficulty)
    SELECT blockNum, proofOfWork, prevFilledBlockHash, difficulty
    FROM records
    WHERE version = NEW.version
    AND blockNum = NEW.blocknum - 1
    OR
    (
        blockNum = NEW.blocknum
        AND prevFilledBlockHash = NEW.prevFilledBlockHash
    )
    ORDER BY blockNum, proofOfWork; --(Because here is no 'window functions')
    
    INSERT INTO NewBlocks(blockNum, blockHash, recordsNum, prevFilledBlockHash, difficulty)
    SELECT
        blockNum,
        hashFunc(proofOfWork) AS blockHash,
        count(*) AS recordsNum,
        prevFilledBlockHash,
        difficulty
    FROM AffectedRecords r
    GROUP BY blockNum, prevFilledBlockHash;
    
    INSERT INTO blocksContents(blockHash, proofOfWork)
    SELECT blockHash, proofOfWork
    FROM NewBlocks b
    JOIN AffectedRecords r USING(prevFilledBlockHash);
    
    INSERT INTO blocks
    (
        blockHash,
        blockNum,
        difficulty,
        recordsNum,
        prevFilledBlockHash
    )
    SELECT 
        blockHash,
        blockNum,
        difficulty,
        recordsNum,
        prevFilledBlockHash
    FROM NewBlocks;
    
    DELETE FROM AffectedRecords;
    DELETE FROM NewBlocks;
    
END;
`;

class Storage
{
    const string path;
    Database db;
    
    private Statement
        qInsertRecAwaitingPublish,
        qSelectOldestRecsAwaitingPublish,
        qUpdateCalculatedPoW,
        qDeleteRecordAwaitingPublish,
        qInsertRecord,
        BEGIN_TRANSACTION,
        COMMIT_TRANSACTION;
    
    this(string filename)
    {
        enforce(threadSafe(), "SQLite3 is not threadsafe");
        
        string home = environment["HOME"];
        string appdir = home~"/.dianna2";
        path = appdir~"/"~filename;
        
        try
            mkdir(appdir);
        catch(FileException e)
            if(e.errno != EEXIST) throw e;
        
        db = Database(path);
        
        sqlite3_create_function(
            db.handle,
            "hashFunc",
            1,
            SQLITE_UTF8,
            null,
            null,
            &xStepSHA1Func,
            &xFinalSHA1Func
        );
        
        db.run(sqlCreateSchema);
        
        qInsertRecAwaitingPublish = db.prepare("
            INSERT INTO recordsAwaitingPublish (
                chainType,
                payloadType,
                payload,
                hash
            )
            VALUES (
                :chainType,
                :payloadType,
                :payload,
                :hash
            )
        ");
        
        qSelectOldestRecsAwaitingPublish = db.prepare("
            SELECT
                chainType,
                payloadType,
                payload,
                hash
            FROM recordsAwaitingPublish
            WHERE chainType = :chainType
            AND (proofOfWork IS NOT NULL) = (:hasPoW != 0)
            ORDER BY rowid
            LIMIT :num
        ");
        
        qUpdateCalculatedPoW = db.prepare("
            UPDATE recordsAwaitingPublish SET
            
            blockNum = :blockNum,
            prevFilledBlockHash = :prevFilledBlockHash,
            proofOfWork = :proofOfWork
                        
            WHERE hash = :hash
        ");
        
        qDeleteRecordAwaitingPublish = db.prepare("
            DELETE FROM recordsAwaitingPublish
            WHERE hash = :hash
        ");
        
        BEGIN_TRANSACTION = db.prepare("BEGIN TRANSACTION");
        COMMIT_TRANSACTION = db.prepare("COMMIT TRANSACTION");
        
        qInsertRecord = db.prepare(
            `INSERT INTO records (
                version,
                chainType,
                payloadType,
                payload,
                hash,
                blockNum,
                prevFilledBlockHash,
                difficulty,
                proofOfWork
            )
            VALUES (
                1,
                :chainType,
                :payloadType,
                :payload,
                :recordHash,
                :blockNum,
                :prevFilledBlockHash,
                :difficulty,
                :proofOfWork
            )`
        );
    }
    
    extern (C)
    private static void xStepSHA1Func(sqlite3_context *ct, int argc, sqlite3_value **argv)
    {
        if (argc != 1)
        {
            sqlite3_result_null(ct);
            return;
        }
        
        auto hash = cast(SHA1*) sqlite3_aggregate_context(ct, SHA1.sizeof);
        
        immutable len = sqlite3_value_bytes(argv[0]);
        const p = cast(ubyte*) sqlite3_value_blob(argv[0]);
        
        hash.put(p[0..len]);
    }
    
    extern (C)
    private static void xFinalSHA1Func(sqlite3_context *ct)
    {
        auto hash = cast(SHA1*) sqlite3_aggregate_context(ct, SHA1.sizeof);
        
        const res = hash.finish;
        
        sqlite3_result_blob(ct, res.ptr, res.sizeof, SQLITE_TRANSIENT);
    }
    
    version(unittest)
    void purge()
    {
        remove(path);
    }
    
    void Insert(in Record r)
    {
        alias e = qInsertRecord;
        
        e.bind(":chainType", r.chainType);
        e.bind(":payloadType", r.payloadType);
        e.bind(":payload", r.payload);
        e.bind(":recordHash", r.hash.getUbytes);
        e.bind(":blockNum", r.blockNum);
        e.bind(":prevFilledBlockHash", r.prevFilledBlock.getUbytes);
        e.bind(":difficulty", r.difficulty);
        e.bind(":proofOfWork", r.proofOfWork.getUbytes);
        
        e.execute();
        assert(db.changes() == 1);
        e.reset();
    }
    
    void addRecordAwaitingPoW(in Record r)
    {
        alias q = qInsertRecAwaitingPublish;
        
        q.bind(":chainType", r.chainType);
        q.bind(":payloadType", r.payloadType);
        q.bind(":payload", r.payload);
        q.bind(":hash", r.hash.getUbytes);
        
        q.execute();
        assert(db.changes() == 1);
        q.reset();
    }
    
    Record[] getOldestRecordsAwaitingPublish(ChainType chainType, bool hasPoW, size_t num)
    {
        alias q = qSelectOldestRecsAwaitingPublish;
        
        q.bind(":chainType", chainType);
        q.bind(":hasPoW", hasPoW ? 1 : 0);
        q.bind(":num", num);
        
        auto queryRes = q.execute();
        
        Record[] res;
        
        foreach(row; queryRes)
        {
            ubyte[] hashRow = row["hash"].as!(ubyte[]);
            
            immutable RecordHash hash = {
                hash: hashRow[0..RecordHash.Hash.sizeof],
                salt: hashRow[RecordHash.Hash.sizeof..RecordHash.Hash.sizeof+RecordHash.Salt.sizeof]
            };
            
            Record r = {
                chainType: chainType,
                payloadType: row["payloadType"].as!PayloadType,
                payload: row["payload"].as!(ubyte[]),
                hash: hash
            };
            
            res ~= r;
        }
        
        q.reset();
        
        return res;
    }
    
    void setCalculatedPoW(in Record r)
    {
        alias q = qUpdateCalculatedPoW;
        
        q.bind(":hash", r.hash.getUbytes);
        q.bind(":blockNum", r.blockNum);
        q.bind(":prevFilledBlockHash", r.prevFilledBlock.getUbytes);
        q.bind(":proofOfWork", r.proofOfWork.getUbytes);
        
        q.execute();
        assert(db.changes() == 1);
        q.reset();
    }
    
    void deleteRecordAwaitingPublish(inout RecordHash h)
    {
        alias q = qDeleteRecordAwaitingPublish;
        
        q.bind(":hash", h.getUbytes);
        
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
    
    r.proofOfWork.hash[0] = 1;
    s.Insert(r);
    r.proofOfWork.hash[0] = 2;
    s.Insert(r);
    r.proofOfWork.hash[0] = 3;
    s.Insert(r);
    
    s.addRecordAwaitingPoW(r);
    
    r.proofOfWork.hash[0..3] = [0x48, 0x48, 0x48];
    s.setCalculatedPoW(r);
    
    auto oldest = s.getOldestRecordsAwaitingPublish(ChainType.Test, true, 3);
    assert(oldest.length == 1);
    
    s.deleteRecordAwaitingPublish(r.hash);
    
    auto oldest2 = s.getOldestRecordsAwaitingPublish(ChainType.Test, true, 3);
    assert(oldest2.length == 0);
    
    s.purge;
}
