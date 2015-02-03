@trusted:

import records;
import d2sqlite3;

import std.exception: enforce;
import std.process: environment;
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
FROM r
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
        qCalcPreviousRecordsNum,
        qSelectNextBlocks,
        qSelectNextParallelBlocks,
        qCalcHash;
    
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
        
        qCalcPreviousRecordsNum = db.prepare(`
            WITH RECURSIVE r(
                blockHash,
                prevFilledBlockHash,
                prevParallelBlockHash,
                primaryRecordsNum,
                blockNum
            ) AS
            (
                SELECT
                    blockHash,
                    prevFilledBlockHash,
                    prevParallelBlockHash,
                    primaryRecordsNum,
                    blockNum
                FROM blocks
                WHERE blockHash = :blockHash
                AND blockNum >= :blockNumLimit
                
                UNION
                
                SELECT
                    b.blockHash,
                    b.prevFilledBlockHash,
                    b.prevParallelBlockHash,
                    b.primaryRecordsNum,
                    b.blockNum
                FROM blocks b
                JOIN r ON b.blockHash = CASE
                    WHEN r.prevParallelBlockHash IS NULL THEN r.prevFilledBlockHash
                    ELSE r.prevParallelBlockHash
                END
                WHERE b.blockNum >= :blockNumLimit
            ),
            
            WithoutLatest(primaryRecordsNum, blockNum) AS
            (
                SELECT primaryRecordsNum, blockNum
                FROM r
                WHERE blockNum <= :blockNumStart
            )
            
            SELECT
            (
                SELECT total(primaryRecordsNum)
                FROM WithoutLatest
                WHERE blockNum < :blockNumDelimiter
            ) AS early,
            (
                SELECT total(primaryRecordsNum)
                FROM WithoutLatest
                WHERE blockNum >= :blockNumDelimiter
            ) AS later
        `);
        
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
    
    private Nullable!Block getBlock(inout BlockHash blockHash)
    {
        alias q = qSelectBlock;
        
        q.bind(":blockHash", blockHash);
        
        auto answer = q.execute();
        
        Nullable!Block nullableResult;
        
        if(answer.empty) return nullableResult;
        
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
    
    private void calcPreviousRecordsNum
    (
        in BlockHash b,
        in uint blockNumStart,
        in uint blockNumDelimiter,
        in uint blockNumLimit,
        out uint early,
        out uint later
    )
    {
        assert(blockNumDelimiter >= blockNumLimit);
        
        alias q = qCalcPreviousRecordsNum;
        
        q.bind(":blockHash", b);
        q.bind(":blockNumStart", blockNumStart);
        q.bind(":blockNumDelimiter", blockNumDelimiter);
        q.bind(":blockNumLimit", blockNumLimit);
        
        auto answer = q.execute();
        auto r = answer.front();
        
        early = r["early"].as!uint;
        later = r["later"].as!uint;
        
        version(assert) answer.popFront;
        assert(answer.empty);
        
        q.reset();
    }
    
    Difficulty calcDifficulty(in Block from)
    {
        assert(from.blockNum >= 1);
        
        alias window = Block.difficultyWindowBlocks;
        
        // Initial difficulty
        if(from.blockNum <= window)
            return 0;
        
        uint early;
        uint later;
        
        const uint start = from.blockNum / window * window;
        const int delimiter = start - window;
        const int limit = start - window * 2;
        
        BlockHash currBlockHash = from.blockHash;
        Difficulty oldDifficulty;
        
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
        
        return oldDifficulty * (later / early);
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
    
    BlockHash findLatestHonestBlock(in Block from, in size_t limitBlockNum)
    {
        return findRecursively(from, limitBlockNum).blockHash;
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
    
    const difficulty = s.calcDifficulty(s.getBlock(latest6));
    
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
