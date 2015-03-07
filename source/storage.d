@trusted:

import records;
import d2sqlite3;

import std.exception: enforce;
import std.path: expandTilde;
import std.file;
import core.stdc.errno;
import std.conv: to;
import std.digest.sha;
import std.typecons: Nullable;


immutable string sqlRecordFields = q"EOS
    chainType INT NOT NULL, -- 0 = real chain, 1 = test chain
    payloadType INT NOT NULL,
    payload BLOB NOT NULL,
    hash BLOB NOT NULL,
EOS";

immutable string sqlCreateSchema =
`CREATE TABLE IF NOT EXISTS records (
`~sqlRecordFields~`
    version INT NOT NULL CHECK (version >= 0),
    blockNum INT NOT NULL CHECK (blockNum >= 0),
    prevFilledBlockHash BLOB,
    difficulty INT NOT NULL CHECK (difficulty >= 0),
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
    blockNum INT NOT NULL CHECK (blockNum >= 0),
    difficulty INT NOT NULL CHECK (difficulty >= 0),
    prevParallelBlockHash BLOB INT,
    prevFilledBlockHash BLOB INT NOT NULL,
    recordsNum INT NOT NULL CHECK (recordsNum > 0),
    primaryRecordsNum INT NOT NULL CHECK (primaryRecordsNum <= recordsNum),
    proofOfWork BLOB NOT NULL, -- record caused this block creation
    isParallelRecord INT NOT NULL, -- boolean: 0 = not parallel, 1 = parallel
    prevIncludedBlockHash BLOB
);

CREATE UNIQUE INDEX IF NOT EXISTS blocks_uniq
ON blocks(blockHash);

CREATE UNIQUE INDEX IF NOT EXISTS blocks_prevIncludedBlockHash_uniq
ON blocks(prevIncludedBlockHash);

CREATE VIEW IF NOT EXISTS BlocksContents AS
WITH RECURSIVE r(
    blockHash,
    proofOfWork,
    isParallelRecord,
    prevIncludedBlockHash
) AS (
    SELECT
        blockHash,
        proofOfWork,
        isParallelRecord,
        prevIncludedBlockHash
    FROM blocks b
    
    UNION
    
    SELECT
        r.blockHash,
        b.proofOfWork,
        b.isParallelRecord,
        b.prevIncludedBlockHash
    FROM blocks b
    JOIN r ON b.blockHash = r.prevIncludedBlockHash
)

SELECT
    blockHash,
    isParallelRecord,
    proofOfWork
FROM r;

CREATE TABLE IF NOT EXISTS Settings (
    key TEXT NOT NULL PRIMARY KEY,
    value BLOB
)
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
        qInsertBlock,
        qSelectBlock,
        qSelectNextMostFilledBlockHash,
        qSelectNextParallelMostFilledBlockHash,
        qSelectNextBlocks,
        qSelectNextParallelBlocks,
        qSelectBlockRecords,
        qCalcHash,
        qSetSetting,
        qGetSetting;
    
    this(in string filename)
    {
        enforce(threadSafe(), "SQLite3 is not threadsafe");
        
        const appdir = expandTilde("~/.dianna2");
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
        
        qInsertBlock = db.prepare(`
            INSERT INTO blocks (
                blockHash,
                blockNum,
                difficulty,
                prevFilledBlockHash,
                prevParallelBlockHash,
                recordsNum,
                primaryRecordsNum,
                isParallelRecord,
                proofOfWork,
                prevIncludedBlockHash
            )
            VALUES (
                :blockHash,
                :blockNum,
                :difficulty,
                :prevFilledBlockHash,
                :prevParallelBlockHash,
                :recordsNum,
                :primaryRecordsNum,
                :isParallelRecord,
                :proofOfWork,
                :prevIncludedBlockHash
            )
        `);
        
        qSelectBlock = db.prepare(`
            SELECT
                blockNum,
                prevFilledBlockHash,
                prevParallelBlockHash,
                recordsNum,
                primaryRecordsNum,
                difficulty,
                prevIncludedBlockHash
            FROM blocks
            WHERE blockHash = :blockHash
        `);
        
        qSelectNextParallelMostFilledBlockHash = db.prepare(`
            SELECT blockHash
            FROM blocks
            WHERE prevParallelBlockHash = :blockHash
            AND blockNum <= :blockNum
            ORDER BY recordsNum DESC
            LIMIT 1
        `);
        
        qSelectNextMostFilledBlockHash = db.prepare(`
            SELECT blockHash
            FROM blocks
            WHERE prevFilledBlockHash = :blockHash
            AND blockNum <= :blockNum
            ORDER BY recordsNum DESC
            LIMIT 1
        `);
        
        qSelectNextBlocks = db.prepare(`
            SELECT blockHash
            FROM blocks
            WHERE prevFilledBlockHash = :fromBlockHash
            AND blockNum <= :limitBlockNum
        `);
        
        qSelectNextParallelBlocks = db.prepare(`
            SELECT blockHash
            FROM blocks
            WHERE prevParallelBlockHash = :fromBlockHash
            AND blockNum <= :limitBlockNum
        `);
        
        qCalcHash = db.prepare(`
            WITH hashes(proofOfWork) AS
            (
                SELECT c.proofOfWork
                FROM blocks
                JOIN BlocksContents c USING(blockHash)
                WHERE blockHash = :blockHash
                
                UNION ALL
                
                SELECT :proofOfWork
            ),
            
            ordered(proofOfWork) AS
            (
                SELECT proofOfWork
                FROM hashes
                ORDER BY proofOfWork
            )
            
            SELECT hashFunc(proofOfWork) AS blockHash
            FROM ordered
        `);
        
        qSetSetting = db.prepare(`
            INSERT OR REPLACE INTO Settings (key, value)
            VALUES (:key, :value)
        `);
        
        qGetSetting = db.prepare(`
            SELECT value
            FROM Settings
            WHERE key = :key
        `);
        
        qSelectBlockRecords = db.prepare(`
            SELECT
                chainType,
                payload,
                hash,
                version,
                blockNum,
                prevFilledBlockHash,
                difficulty,
                proofOfWork
                
            FROM BlocksContents b
            JOIN records r USING(proofOfWork)
            WHERE blockHash = :blockHash
            AND payloadType = :payloadType
            AND version = 1
        `);
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
    
    // TODO: it is really need?
    version(unittest)
    void writeInitialBlockHashSetting()
    {
        Storage.Block ib;
        
        setSetting("rootBlockHash", ib.blockHash);
    }
    
    void addRecord(in Record r)
    {
        db.begin;
        
        insertRecord(r);
        
        const curr = getNextMostFilledBlock(r.prevFilledBlock, r.blockNum);
        
        Block nb; /// New current block
        
        nb.prevFilledBlockHash = r.prevFilledBlock;
        nb.blockNum = r.blockNum;
        nb.isParallelRecord = false;
        nb.proofOfWork = r.proofOfWork;
        nb.difficulty = r.difficulty;
        
        Block currBlock;
        if(!curr.isNull) currBlock = getBlock(curr);
        
        const bool needNewBlock = curr.isNull || currBlock.blockNum < r.blockNum;
        
        if(needNewBlock)
        {
            // New block with one record
            nb.blockHash = calcHashForOneRecord(nb.proofOfWork);
            nb.recordsNum = 1;
            nb.primaryRecordsNum = 1;
        }
        else
        {
            // Next record to current block
            nb.blockHash = calcHash(curr, nb.proofOfWork);
            nb.recordsNum = currBlock.recordsNum + 1;
            nb.primaryRecordsNum = currBlock.primaryRecordsNum + 1;
        }
        
        Nullable!BlockHash para;
        
        if(currBlock.blockNum + 1 == r.blockNum)
            para = curr;
        else
            para = getNextParallelMostFilledBlock(r.prevFilledBlock, r.blockNum);
        
        Block npb; /// New parallel block
        if(!para.isNull) npb = getBlock(para);
        
        if(!para.isNull && npb.blockNum + 1 == r.blockNum)
        {
            // Next record to parallel block
            npb = getBlock(para);
            
            npb.blockHash = calcHash(para, r.proofOfWork);
            npb.recordsNum++;
            npb.isParallelRecord = true;
            npb.proofOfWork = r.proofOfWork;
            
            insertBlock(npb);
            
            nb.prevParallelBlockHash = npb.blockHash;
        }
        
        insertBlock(nb);
        
        db.commit;
    }
    
    private BlockHash calcHash(in BlockHash blockHash, in PoW proofOfWork)
    {
        alias q = qCalcHash;
        
        q.bind(":blockHash", blockHash);
        q.bind(":proofOfWork", proofOfWork.getUbytes);
        
        auto answer = q.execute();
        
        const BlockHash res = (answer.oneValue!(ubyte[]))[0..BlockHash.length];
        
        q.reset();
        
        return res;
    }
    
    private BlockHash calcHashForOneRecord(in PoW proofOfWork)
    {
        alias q = qCalcHash;
        
        BlockHash unavailable;
        
        foreach(ref e; unavailable)
            e = 0xFF;
        
        q.bind(":blockHash", unavailable);
        q.bind(":proofOfWork", proofOfWork.getUbytes);
        
        auto answer = q.execute();
        
        const BlockHash res = (answer.oneValue!(ubyte[]))[0..BlockHash.length];
        
        q.reset();
        
        return res;
    }
    
    private void insertRecord(in Record r)
    {
        alias e = qInsertRecord;
        
        e.bind(":chainType", r.chainType);
        e.bind(":payloadType", r.payloadType);
        e.bind(":payload", r.payload);
        e.bind(":recordHash", r.hash.getUbytes);
        e.bind(":blockNum", r.blockNum);
        e.bind(":prevFilledBlockHash", r.prevFilledBlock);
        e.bind(":difficulty", r.difficulty);
        e.bind(":proofOfWork", r.proofOfWork.getUbytes);
        
        e.execute();
        assert(db.changes() == 1);
        e.reset();
    }
    
    struct Block
    {
        BlockHash blockHash;
        BlockHash prevFilledBlockHash;
        Nullable!BlockHash prevParallelBlockHash;
        Nullable!BlockHash prevIncludedBlockHash;
        uint blockNum;
        Difficulty difficulty;
        size_t recordsNum;
        size_t primaryRecordsNum;
        Nullable!PoW proofOfWork;
        Nullable!bool isParallelRecord;
        
        static immutable blockDurationHours = 12;
        static immutable difficultyWindowBlocks = blockDurationHours * 2 * 7; /// One week
    }
    
    private void insertBlock(inout Block b)
    {
        alias q = qInsertBlock;
        
        q.bind(":blockHash", b.blockHash);
        q.bind(":prevFilledBlockHash", b.prevFilledBlockHash);
        q.bind(":blockNum", b.blockNum);
        q.bind(":difficulty", b.difficulty);
        q.bind(":recordsNum", b.recordsNum);
        q.bind(":primaryRecordsNum", b.primaryRecordsNum);
        q.bind(":isParallelRecord", b.isParallelRecord ? 1 : 0);
        q.bind(":proofOfWork", b.proofOfWork.getUbytes);
        
        if(b.prevParallelBlockHash.isNull)
            q.bind(":prevParallelBlockHash", null);
        else
            q.bind(":prevParallelBlockHash", b.prevParallelBlockHash.get);
        
        if(b.prevIncludedBlockHash.isNull)
            q.bind(":prevIncludedBlockHash", null);
        else
            q.bind(":prevIncludedBlockHash", b.prevIncludedBlockHash.get);
        
        q.execute();
        assert(db.changes() == 1);
        q.reset();
    }
    
    private Nullable!Block getBlock(in BlockHash blockHash)
    {
        alias q = qSelectBlock;
        
        q.bind(":blockHash", blockHash);
        
        auto answer = q.execute();
        
        Nullable!Block nullableResult;
        
        if(!answer.empty)
        {
            auto r = answer.front();
            
            Block res;
            res.blockHash = blockHash;
            res.blockNum = r["blockNum"].as!uint;
            res.difficulty = r["difficulty"].as!Difficulty;
            res.prevFilledBlockHash = (r["prevFilledBlockHash"].as!(ubyte[]))[0..BlockHash.length];
            res.recordsNum = r["recordsNum"].as!size_t;
            res.primaryRecordsNum = r["primaryRecordsNum"].as!size_t;
            
            if(r["prevParallelBlockHash"].as!(ubyte[]).length)
                res.prevParallelBlockHash = (r["prevParallelBlockHash"].as!(ubyte[]))[0..BlockHash.length];
            
            if(r["prevIncludedBlockHash"].as!(ubyte[]).length)
                res.prevIncludedBlockHash = (r["prevIncludedBlockHash"].as!(ubyte[]))[0..BlockHash.length];
            
            nullableResult = res;
            
            version(assert) answer.popFront;
            assert(answer.empty);
        }
        
        q.reset();
        
        return nullableResult;
    }
    
    private Nullable!BlockHash getNextMostFilledBlock(in BlockHash blockHash, in size_t blockNumLimit)
    {
        alias q = qSelectNextMostFilledBlockHash;
        
        q.bind(":blockHash", blockHash);
        q.bind(":blockNum", blockNumLimit);
        
        auto answer = q.execute();
        
        Nullable!BlockHash res;
        
        if(!answer.empty)
            res = (answer.oneValue!(ubyte[]))[0..BlockHash.length];
        
        q.reset();
        
        return res;
    }
    
    private Nullable!BlockHash getNextParallelMostFilledBlock(in BlockHash blockHash, in size_t blockNumLimit)
    {
        alias q = qSelectNextParallelMostFilledBlockHash;
        
        q.bind(":blockHash", blockHash);
        q.bind(":blockNum", blockNumLimit);
        
        auto answer = q.execute();
        
        Nullable!BlockHash res;
        
        if(!answer.empty)
            res = (answer.oneValue!(ubyte[]))[0..BlockHash.length];
        
        q.reset();
        
        return res;
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
            
            immutable RecordHash hash = RecordHash.createFrom(hashRow);
            
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
        q.bind(":prevFilledBlockHash", r.prevFilledBlock);
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
    
    Difficulty calcDifficulty(in Block from)
    {
        assert(from.blockNum >= 1);
        
        alias window = Block.difficultyWindowBlocks;
        
        Difficulty oldDifficulty = 0;
        
        // Initial difficulty
        if(from.blockNum < window * 2)
            return oldDifficulty;
        
        const uint start = from.blockNum / window * window;
        
        assert(start >= window * 2);
        
        const uint delimiter = start - window;        
        const uint limit = start - window * 2;
        
        uint early;
        uint later;
        
        BlockHash currBlockHash = from.blockHash;
        
        while(true)
        {
            const cb = getBlock(currBlockHash); /// current block
            
            if(cb.isNull || cb.blockNum < limit) break;
            
            if(cb.blockNum <= start)
            {
                if(cb.blockNum < delimiter)
                {
                    early += cb.primaryRecordsNum;
                    oldDifficulty = cb.difficulty;
                }
                else
                    later += cb.primaryRecordsNum;
            }
            
            if(cb.prevParallelBlockHash.isNull)
                currBlockHash = cb.prevFilledBlockHash;
            else
                currBlockHash = cb.prevParallelBlockHash;
        }
        
        enforce(early);
        
        if(!oldDifficulty) oldDifficulty = 1;
        
        return oldDifficulty * later / early;
    }
    
    private Block[] getNextBlocks
    (
        in BlockHash fromBlockHash,
        in size_t limitBlockNum
    )
    {
        alias q = qSelectNextBlocks;
        
        q.bind(":fromBlockHash", fromBlockHash);
        q.bind(":limitBlockNum", limitBlockNum);
        
        auto answer = q.execute();
        
        Block[] res;
        
        foreach(ref r; answer)
        {
            const BlockHash h = (r["blockHash"].as!(ubyte[]))[0..BlockHash.length];
            
            res ~= getBlock(h);
        }
        
        q.reset();
        
        return res;
    }
    
    private BlockHash[] getParallelBlocks
    (
        in BlockHash fromBlockHash,
        in size_t parallelBlockNum
    )
    {
        alias q = qSelectNextParallelBlocks;
        
        q.bind(":fromBlockHash", fromBlockHash);
        q.bind(":limitBlockNum", parallelBlockNum);
        
        auto answer = q.execute();
        
        BlockHash[] res;
        
        foreach(ref r; answer)
        {
            BlockHash h = (r["blockHash"].as!(ubyte[]))[0..BlockHash.length];
            
            res ~= h;
        }
        
        q.reset();
        
        return res;
    }
    
    private struct Weight
    {
        ulong spentCPU;
        BlockHash blockHash;
    }
    
    private Weight findRecursively(in Block from, in size_t limitBlockNum)
    {
        Block[] toProcess;
        
        if(from.blockNum < limitBlockNum)
        {
            const pb = getParallelBlocks(from.blockHash, from.blockNum + 1);
            
            foreach(ref h; pb)
                toProcess ~= getBlock(h);
        }
        
        if(toProcess.length == 0)
            toProcess = getNextBlocks(from.blockHash, limitBlockNum);
        
        const Weight currWeight = {
            spentCPU: from.primaryRecordsNum * from.difficulty,
            blockHash: from.blockHash
        };
        
        // Path finding
        if(toProcess.length == 0)
        {
            return currWeight;
        }
        else
        {
            Weight[] res = new Weight[toProcess.length];
            
            foreach(size_t i, ref b; toProcess)
                res[i] = findRecursively(b, limitBlockNum);
            
            size_t maxKey;
            
            foreach(size_t i, ref w; res)
            {
                // Most CPU spent branch
                if(w.spentCPU > res[maxKey].spentCPU)
                    maxKey = i;
            }
            
            res[maxKey].spentCPU += currWeight.spentCPU;
            
            return res[maxKey];
        }
    }
    
    BlockHash findLatestHonestBlock(in size_t limitBlockNum)
    {
        //FIXME: chainType forgotten
        const val = getSetting("rootBlockHash");
        
        enforce(val.length == BlockHash.length);
        
        const BlockHash h = val[0..BlockHash.length];
        
        const Block b = getBlock(h);
        
        return findLatestHonestBlock(b, limitBlockNum);
    }
    
    private BlockHash findLatestHonestBlock(in Block from, in size_t limitBlockNum)
    {
        return findRecursively(from, limitBlockNum).blockHash;
    }
    
    private BlockHash getPrevBlock(in Block b)
    {
        return b.prevParallelBlockHash.isNull ?
            b.prevFilledBlockHash : b.prevParallelBlockHash;
    }
    
    void setSetting(in string key, in ubyte[] value)
    {
        alias q = qSetSetting;
        
        q.bind(":key", key);
        q.bind(":value", value);
        
        auto answer = q.execute();
        assert(db.changes() == 1);
        q.reset();
    }
    
    ubyte[] getSetting(in string key)
    {
        alias q = qGetSetting;
        
        q.bind(":key", key);
        
        auto answer = q.execute();
        
        ubyte[] res;
        
        if(!answer.empty)
            res = answer.oneValue!(ubyte[]);
        
        q.reset();
        
        return res;
    }
    
    Record[] getBlockRecords(in BlockHash b, in PayloadType pt)
    {
        alias q = qSelectBlockRecords;
        
        q.bind(":blockHash", b);
        q.bind(":payloadType", pt);
        
        auto answer = q.execute();
        
        Record[] res;
        
        foreach(ref a; answer)
        {
            Record r;
            r.chainType = a["chainType"].as!ChainType;
            r.payloadType = pt;
            r.payload = a["payload"].as!(ubyte[]);
            r.hash = RecordHash((a["hash"].as!(ubyte[]))[0..RecordHash.length]);
            r.blockNum = a["blockNum"].as!uint;
            r.prevFilledBlock = (a["prevFilledBlock"].as!(ubyte[]))[0..BlockHash.length];
            r.difficulty = a["difficulty"].as!Difficulty;
            r.proofOfWork = a["proofOfWork"].as!PoW;
            
            res ~= r;
        }
        
        q.reset();
        
        return res;
    }
    
    /// Calls delegate for all records from latest to first block in blockchain
    void followByChain(
        in ChainType chainType,
        in PayloadType payloadType,
        in string key,
        bool delegate(Record) dg
    )
    {
        db.begin();
        
        Nullable!Block curr = getBlock(
            findLatestHonestBlock(
                calcCurrentFilledBlockNum()
            )
        );
        
        do{
            Record[] recs = getBlockRecords(curr.blockHash, payloadType);
            
            foreach(ref r; recs)
                dg(r);
            
            curr = getBlock(getPrevBlock(curr));
        }
        while(!curr.isNull);
        
        db.commit();
    }
    
    // TODO:
    bool validate(in Record r)
    {
        if(!isSatisfyDifficulty(r.proofOfWork.hash, r.difficulty)) return false;
        
        const src = r.getFullRecordHashSource();
        if(!isValidPoW(src, r.proofOfWork)) return false;
        
        const b = getBlock(r.prevFilledBlock);
        
        if(b.isNull) return false; // can't be validated
        if(b.blockNum >= r.blockNum) return false;
        
        const difficulty = calcDifficulty(b);
        if(difficulty != r.difficulty) return false;
        
        return true;
    }
}

unittest
{
    auto s = new Storage("_unittest_storage.sqlite");
    
    Storage.Block prevFilledBlock;
    prevFilledBlock.blockHash[0] = 88;
    
    const latest1 = s.findLatestHonestBlock(prevFilledBlock, 8);
    assert(latest1 == prevFilledBlock.blockHash);
    
    Record r = {
        chainType: ChainType.Test,
        payloadType: PayloadType.Test,
        payload: [0x76, 0x76, 0x76, 0x76],
        blockNum: 1,
        difficulty: 1,
        prevFilledBlock: prevFilledBlock.blockHash
    };
    
    r.proofOfWork.hash[5] = 0x31;
    s.addRecord(r);
    
    const latest2 = s.findLatestHonestBlock(prevFilledBlock, 8);
    assert(latest2 != latest1);
    
    r.proofOfWork.hash[5] = 0x32;
    s.addRecord(r);
    
    const latest3 = s.findLatestHonestBlock(prevFilledBlock, 8);
    assert(latest3 != latest2);
    assert(latest3 != latest1);
    
    Record r2 = r; // parallel block
    r2.blockNum = 2;
    r2.proofOfWork.hash[5] = 0x34;
    s.addRecord(r2);
    
    const latest4 = s.findLatestHonestBlock(prevFilledBlock, 8);
    assert(latest4 != latest3);
    
    Record r3 = r; // next block
    r3.prevFilledBlock = latest3;
    r3.blockNum = 3;
    r3.proofOfWork.hash[5] = 0x35;
    s.addRecord(r3);
    
    const latest5_1 = s.findLatestHonestBlock(prevFilledBlock, 8);
    assert(latest5_1 != latest4);
    
    // next block again
    r3.proofOfWork.hash[5] = 0x39;
    s.addRecord(r3);
    
    const latest5 = s.findLatestHonestBlock(prevFilledBlock, 8);
    assert(latest5 != latest5_1);
    
    Record r4 = r; // not relevant parallel block
    r4.prevFilledBlock = latest4;
    r4.blockNum = 4;
    r4.proofOfWork.hash[5] = 0x36;
    s.addRecord(r4);
    
    const latest6 = s.findLatestHonestBlock(prevFilledBlock, 8);
    assert(latest6 == latest5);
    
    const difficulty1 = s.calcDifficulty(s.getBlock(latest6));
    assert(difficulty1 == 0);
    
    Record r5 = r4;
    r5.proofOfWork.hash[5] = 0x37;
    r5.prevFilledBlock = latest5;
    r5.blockNum = Storage.Block.difficultyWindowBlocks * 2;
    s.addRecord(r5);
    
    const latest7 = s.findLatestHonestBlock(prevFilledBlock, Storage.Block.difficultyWindowBlocks * 50);
    assert(latest7 != latest5);
    
    Record r6 = r4;
    r6.proofOfWork.hash[5] = 0x38;
    r6.prevFilledBlock = latest7;
    r6.blockNum = Storage.Block.difficultyWindowBlocks * 2 + 1;
    s.addRecord(r6);
    
    const latest8 = s.findLatestHonestBlock(prevFilledBlock, Storage.Block.difficultyWindowBlocks * 50);
    assert(latest8 != latest7);
    
    const difficulty2 = s.calcDifficulty(s.getBlock(latest8));
    assert(difficulty2 == 0);
    
    auto isValid = s.validate(r6);
    //assert(isValid);
    
    s.addRecordAwaitingPoW(r);
    
    r.proofOfWork.hash[0..3] = [0x48, 0x48, 0x48];
    s.setCalculatedPoW(r);
    
    auto oldest = s.getOldestRecordsAwaitingPublish(ChainType.Test, true, 3);
    assert(oldest.length == 1);
    
    s.deleteRecordAwaitingPublish(r.hash);
    
    auto oldest2 = s.getOldestRecordsAwaitingPublish(ChainType.Test, true, 3);
    assert(oldest2.length == 0);
    
    immutable key = "test key";
    const value1 = cast(ubyte[]) "test value 1";
    const value2 = cast(ubyte[]) "test value 2";
    
    assert(s.getSetting(key) == null);
    
    s.setSetting(key, value1);
    assert(s.getSetting(key) == value1);
    
    s.setSetting(key, value2);
    assert(s.getSetting(key) == value2);
    
    s.setSetting(key, null);
    assert(s.getSetting(key) == null);
    
    s.purge;
}
