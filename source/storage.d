@trusted:

import records;
import d2sqlite3;

import std.process: environment;
import std.file;
import core.stdc.errno;

immutable string sqlRecordFields = q"EOS
    version INT NOT NULL,
    chain INT NOT NULL, -- 0 = real chain, 1 = test chain
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

CREATE TABLE IF NOT EXISTS recordsAwaitingPoW (
`~sqlRecordFields~`
    blockNum INT,
    prevFilledBlockHash BLOB,
    proofOfWorkHash BLOB,
    proofOfWorkSalt BLOB
);

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
    
    private Query qInsertRec;
    private Query qInsertRecAwaitingPoW;
    
    this(string filename)
    {
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
    chain,
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
        
        qInsertRecAwaitingPoW = db.query("
            INSERT INTO recordsAwaitingPoW (
                version,
                chain,
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
    }
    
    version(unittest)
    void purge()
    {
        destroy(qInsertRec);
        destroy(qInsertRecAwaitingPoW);
        destroy(db);
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
        alias q = qInsertRecAwaitingPoW;
        
        q.bind(":chainType", r.chainType);
        q.bind(":key", r.key);
        q.bind(":value", r.value);
        q.bind(":signature", r.signature);
        
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
    s.Insert(r);
    s.Insert(r);
    
    s.purge;
}
