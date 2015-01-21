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
    prevFilledBlockHash BLOB INT NOT NULL,
    recordsNum INT NOT NULL CHECK (recordsNum > 0),
    proofOfWork BLOB NOT NULL, -- record caused this block creation
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
    prevIncludedBlockHash
) AS (
    SELECT
        blockHash,
        proofOfWork,
        prevIncludedBlockHash
    FROM blocks b
    
    UNION ALL
    
    SELECT
        r.blockHash,
        b.proofOfWork,
        b.prevIncludedBlockHash
    FROM blocks b
    JOIN r ON b.blockHash = r.prevIncludedBlockHash
)

SELECT
    blockHash,
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
        qSelectMostFilledBlock,
        qSelectMostFilledBlockWithPrevHash,
        qSelectBlocks,
        qCalcPreviousRecordsNum,
        qFindNextBlocks,
        qFindParallelBlocks,
        qCreateBlockFromRecord,
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
            WITH RECURSIVE r(prevFilledBlockHash, recordsNum, depth) AS
            (
                SELECT prevFilledBlockHash, recordsNum, 0 AS depth
                FROM blocks b1
                WHERE blockHash = :blockHash
                UNION ALL
                SELECT b2.prevFilledBlockHash, b2.recordsNum, depth + 1 AS depth
                FROM blocks b2
                JOIN r ON b2.blockHash = r.prevFilledBlockHash
                WHERE r.depth < 14
            ),
            
            o(recordsNum) AS
            (
                SELECT recordsNum
                FROM r
                ORDER BY depth
            )
            
            SELECT
                (SELECT sum(recordsNum) FROM o LIMIT 7 OFFSET 7) AS early,
                (SELECT sum(recordsNum) FROM o LIMIT 7) AS later
        `);
        
        qInsertBlock = db.prepare(`
            INSERT INTO blocks (
                blockHash,
                blockNum,
                prevFilledBlockHash,
                recordsNum,
                proofOfWork,
                prevIncludedBlockHash
            )
            VALUES (
                :blockHash,
                :blockNum,
                :prevFilledBlockHash,
                :recordsNum,
                :proofOfWork,
                :prevIncludedBlockHash
            )
        `);
        
        qSelectBlock = db.prepare(`
            SELECT
                blockNum,
                prevFilledBlockHash,
                recordsNum,
                prevIncludedBlockHash
            FROM blocks
            WHERE blockHash = :blockHash
        `);
        
        qSelectMostFilledBlock = db.prepare(`
            SELECT
                blockHash,
                prevFilledBlockHash,
                recordsNum,
                prevIncludedBlockHash
            FROM blocks
            WHERE blockNum = :blockNum
            ORDER BY recordsNum DESC
            LIMIT 1
        `);
        
        qSelectMostFilledBlockWithPrevHash = db.prepare(`
            SELECT
                blockHash,
                prevFilledBlockHash,
                recordsNum,
                prevIncludedBlockHash
            FROM blocks
            WHERE blockNum = :blockNum
            AND prevFilledBlockHash = :prevFilledBlockHash
            ORDER BY recordsNum DESC
            LIMIT 1
        `);
        
        qSelectBlocks = db.prepare(`
            SELECT
                blockHash,
                prevFilledBlockHash,
                recordsNum,
                prevIncludedBlockHash
            FROM blocks
            WHERE blockNum = :blockNum
        `);
        
        qFindNextBlocks = db.prepare(`
            SELECT
                blockHash,
                blockNum,
                prevFilledBlockHash,
                recordsNum,
                prevIncludedBlockHash
            FROM blocks
            WHERE prevFilledBlockHash = :fromBlockHash
            AND blockNum <= :limitBlockNum
        `);
        
        qFindParallelBlocks = db.prepare(`
            WITH b(blockNum, blockHash, proofOfWork) AS
            (
                SELECT blockNum, blockHash, c.proofOfWork
                FROM blocks
                JOIN BlocksContents c USING(blockHash)
            ),
            
            parallelBlocks(blockHash, proofOfWork) AS
            (
                SELECT blockHash, proofOfWork
                FROM b
                WHERE blockNum = :parallelBlockNum
            )
            
            SELECT DISTINCT p.blockHash AS blockHash
            FROM parallelBlocks p
            JOIN b USING(proofOfWork)
            WHERE b.blockHash = :fromBlockHash
        `);
        
        qCreateBlockFromRecord = db.prepare(`
            WITH hashSrc(proofOfWork) AS
            (
                SELECT c.proofOfWork
                FROM blocks
                JOIN BlocksContents c USING(blockHash)
                WHERE prevFilledBlockHash = :prevFilledBlockHash
                AND blockNum = :blockNum
                
                UNION ALL
                
                SELECT :proofOfWork
            )
            
            SELECT
                (
                    SELECT hashFunc(proofOfWork) AS blockHash
                    FROM hashSrc
                    ORDER BY proofOfWork
                ) AS blockHash,
                (
                    SELECT count(proofOfWork)
                    FROM hashSrc
                ) AS recordsNum,
                (
                    SELECT blockHash
                    FROM blocks
                    WHERE prevFilledBlockHash = :prevFilledBlockHash
                    AND blockNum = :blockNum
                    ORDER BY recordsNum DESC
                    LIMIT 1
                ) AS prevIncludedBlockHash
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
        
        // Add to the current block
        {
            Block b;
            
            b.prevFilledBlockHash = r.prevFilledBlock;
            b.blockNum = r.blockNum;
            b.proofOfWork = r.proofOfWork;
            
            Block curr;
            
            const bool isNewBlock = !getMostFilledBlockWithPrevBlock(
                b.prevFilledBlockHash,
                b.blockNum,
                curr
            );
            
            if(isNewBlock)
            {
                b.blockHash = calcHash(r.proofOfWork);
                b.recordsNum = 1;
            }
            else
            {
                b.prevIncludedBlockHash = curr.blockHash;
                b.blockHash = calcHash(curr.blockHash, r.proofOfWork);
                b.recordsNum = curr.recordsNum + 1;
            }
            
            insertBlock(b);
        }
        
        // Add to current-1 block
        {
            Block b;
            
            b.blockNum = r.blockNum - 1;
            
            Block prev;
            
            const bool prevBlockFound = getMostFilledBlock(
                b.blockNum,
                prev
            );
            
            if(prevBlockFound)
            {
                b.prevFilledBlockHash = prev.prevFilledBlockHash;
                b.prevIncludedBlockHash = prev.blockHash;
                b.blockHash = calcHash(prev.blockHash, r.proofOfWork);
                b.recordsNum = prev.recordsNum + 1;
                b.proofOfWork = r.proofOfWork;
                
                insertBlock(b);
            }
        }
        
        db.commit;
    }
    
    private Block createBlock(in Record rec)
    {
        alias q = qCreateBlockFromRecord;
        
        q.bind(":prevFilledBlockHash", rec.prevFilledBlock);
        q.bind(":blockNum", rec.blockNum);
        q.bind(":proofOfWork", rec.proofOfWork.getUbytes);
        
        auto answer = q.execute();
        auto r = answer.front();
        
        Block res;
        res.blockHash = (r["blockHash"].as!(ubyte[]))[0..BlockHash.length];
        res.blockNum = rec.blockNum;
        res.prevFilledBlockHash = rec.prevFilledBlock;
        res.recordsNum = r["recordsNum"].as!size_t;
        
        if(r["prevIncludedBlockHash"].as!(ubyte[]).length)
            res.prevIncludedBlockHash = (r["prevIncludedBlockHash"].as!(ubyte[]))[0..BlockHash.length];
        
        version(assert) answer.popFront;
        assert(answer.empty);
        
        q.reset();
        
        return res;
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
    
    private BlockHash calcHash(in PoW proofOfWork)
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
        Nullable!BlockHash prevIncludedBlockHash;
        size_t blockNum;
        size_t recordsNum;
        PoW proofOfWork;
    }
    
    private void insertBlock(inout Block b)
    {
        alias q = qInsertBlock;
        
        q.bind(":blockHash", b.blockHash);
        q.bind(":prevFilledBlockHash", b.prevFilledBlockHash);
        q.bind(":blockNum", b.blockNum);
        q.bind(":recordsNum", b.recordsNum);
        q.bind(":proofOfWork", b.proofOfWork.getUbytes);
        
        if(b.prevIncludedBlockHash.isNull)
            q.bind(":prevIncludedBlockHash", null);
        else
            q.bind(":prevIncludedBlockHash", b.prevIncludedBlockHash.get);
        
        q.execute();
        assert(db.changes() == 1);
        q.reset();
    }
    
    private Block getBlock(inout BlockHash blockHash)
    {
        alias q = qSelectBlock;
        
        q.bind(":blockHash", blockHash);
        
        auto answer = q.execute();
        auto r = answer.front();
        
        Block res;
        res.blockHash = blockHash;
        res.blockNum = r["blockNum"].as!size_t;
        res.prevFilledBlockHash = (r["prevFilledBlockHash"].as!(ubyte[]))[0..BlockHash.length];
        res.recordsNum = r["recordsNum"].as!size_t;
        
        if(r["prevIncludedBlockHash"].as!(ubyte[]).length)
            res.prevIncludedBlockHash = (r["prevIncludedBlockHash"].as!(ubyte[]))[0..BlockHash.length];
        
        version(assert) answer.popFront;
        assert(answer.empty);
        
        q.reset();
        
        return res;
    }
    
    private bool getMostFilledBlock(in size_t blockNum, out Block res)
    {
        alias q = qSelectMostFilledBlock;
        
        q.bind(":blockNum", blockNum);
        
        auto answer = q.execute();
        
        if(answer.empty)
        {
            q.reset();
            
            return false;
        }
        
        auto r = answer.front();
        
        res.blockHash = (r["blockHash"].as!(ubyte[]))[0..BlockHash.length];
        res.blockNum = blockNum;
        res.prevFilledBlockHash = (r["prevFilledBlockHash"].as!(ubyte[]))[0..BlockHash.length];
        res.recordsNum = r["recordsNum"].as!size_t;
        
        if(r["prevIncludedBlockHash"].as!(ubyte[]).length)
            res.prevIncludedBlockHash = (r["prevIncludedBlockHash"].as!(ubyte[]))[0..BlockHash.length];
        
        version(assert) answer.popFront;
        assert(answer.empty);
        
        q.reset();
        
        return true;
    }
    
    private bool getMostFilledBlockWithPrevBlock(in BlockHash prevFilledBlock, in size_t blockNum, out Block res)
    {
        alias q = qSelectMostFilledBlockWithPrevHash;
        
        q.bind(":blockNum", blockNum);
        q.bind(":prevFilledBlockHash", prevFilledBlock);
        
        auto answer = q.execute();
        
        if(answer.empty)
        {
            q.reset();
            
            return false;
        }
        
        auto r = answer.front();
        
        res.blockHash = (r["blockHash"].as!(ubyte[]))[0..BlockHash.length];
        res.blockNum = blockNum;
        res.prevFilledBlockHash = prevFilledBlock;
        res.recordsNum = r["recordsNum"].as!size_t;
        
        if(r["prevIncludedBlockHash"].as!(ubyte[]).length)
            res.prevIncludedBlockHash = (r["prevIncludedBlockHash"].as!(ubyte[]))[0..BlockHash.length];
        
        version(assert) answer.popFront;
        assert(answer.empty);
        
        q.reset();
        
        return true;
    }
    
    private Block[] getBlock(in size_t blockNum)
    {
        alias q = qSelectBlocks;
        
        q.bind(":blockNum", blockNum);
        
        auto answer = q.execute();
        
        Block[] res;
        
        foreach(r; answer)
        {
            Block b;
            b.blockHash = (r["blockHash"].as!(ubyte[]))[0..BlockHash.length];
            b.blockNum = blockNum;
            b.prevFilledBlockHash = (r["prevFilledBlockHash"].as!(ubyte[]))[0..BlockHash.length];
            b.recordsNum = r["recordsNum"].as!size_t;
            
            if(r["prevIncludedBlockHash"].as!(ubyte[]).length)
                b.prevIncludedBlockHash = (r["prevIncludedBlockHash"].as!(ubyte[]))[0..BlockHash.length];
            
            res ~= b;
        }
        
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
    
    deprecated
    void calcPreviousRecordsNum(in BlockHash b, out uint early, out uint later)
    {
        alias q = qCalcPreviousRecordsNum;
        
        q.bind(":blockHash", b);
        
        auto answer = q.execute();
        auto r = answer.front();
        
        early = r["early"].as!uint;
        later = r["later"].as!uint;
        
        version(assert) answer.popFront;
        assert(answer.empty);
        
        q.reset();
    }
    
    private Block[] findNextBlocks
    (
        in BlockHash fromBlockHash,
        in size_t limitBlockNum
    )
    {
        alias q = qFindNextBlocks;
        
        q.bind(":fromBlockHash", fromBlockHash);
        q.bind(":limitBlockNum", limitBlockNum);
        
        auto answer = q.execute();
        
        Block[] res;
        
        foreach(ref r; answer)
        {
            Block b;
            b.blockNum = r["blockNum"].as!size_t;
            b.recordsNum = r["recordsNum"].as!size_t;
            b.blockHash = (r["blockHash"].as!(ubyte[]))[0..BlockHash.length];
            b.prevFilledBlockHash = (r["prevFilledBlockHash"].as!(ubyte[]))[0..BlockHash.length];
            
            if(r["prevIncludedBlockHash"].as!(ubyte[]).length)
                b.prevIncludedBlockHash = (r["prevIncludedBlockHash"].as!(ubyte[]))[0..BlockHash.length];
            
            res ~= b;
        }
        
        q.reset();
        
        return res;
    }
    
    private BlockHash[] findParallelBlocks
    (
        in BlockHash fromBlockHash,
        in size_t parallelBlockNum
    )
    {
        alias q = qFindParallelBlocks;
        
        q.bind(":fromBlockHash", fromBlockHash);
        q.bind(":parallelBlockNum", parallelBlockNum);
        
        auto answer = q.execute();
        
        BlockHash[] res;
        
        foreach(ref r; answer)
        {
            BlockHash b = (r["blockHash"].as!(ubyte[]))[0..BlockHash.length];
            
            res ~= b;
        }
        
        q.reset();
        
        return res;
    }
    
    private struct Weight
    {
        size_t nodesNum;
        size_t recordsNum;
        BlockHash blockHash;
    }
    
    private Weight findRecursively(in Block from, in size_t limitBlockNum)
    {
        Block[] toProcess;
        
        if(from.blockNum < limitBlockNum)
        {
            const pb = findParallelBlocks(from.blockHash, from.blockNum + 1);
            
            foreach(ref h; pb)
                toProcess ~= getBlock(h);
        }
        
        if(toProcess.length == 0)
            toProcess = findNextBlocks(from.blockHash, limitBlockNum);
        
        // Path finding
        if(toProcess.length == 0)
        {
            // Current block is a leaf
            const Weight currWeight = {
                recordsNum: from.recordsNum,
                blockHash: from.blockHash
            };
            
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
                // Longest branch?
                if(w.nodesNum > res[maxKey].nodesNum)
                {
                    maxKey = i;
                }
                else
                {
                    // More leaf nodes for equal branches
                    if(w.nodesNum == res[maxKey].nodesNum)
                        if(w.recordsNum > res[maxKey].recordsNum)
                            maxKey = i;
                }
            }
            
            ++res[maxKey].nodesNum;
            
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
    r3.prevFilledBlock = latest3;
    r3.proofOfWork.hash[5] = 0x39;
    s.addRecord(r3);
    
    const latest5 = s.findLatestHonestBlock(prevFilledBlock, 8);
    assert(latest5 != latest5_1);
    
    Record r4 = r; // parallel block
    r4.prevFilledBlock = latest4;
    r4.blockNum = 4;
    r4.proofOfWork.hash[5] = 0x36;
    s.addRecord(r4);
    
    const latest6 = s.findLatestHonestBlock(prevFilledBlock, 8);
    assert(latest6 != latest5);
    
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
