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
        qSelectAffectedBlocks,
        qCalcBlockEnclosureChainHash,
        qInsertBlock,
        qSelectBlock,
        qCalcPreviousRecordsNum,
        qFindNextBlock,
        qFindNextBlocks,
        qFindParallelBlocks,
        qFindParallelBlocksWithoutNextBlock,
        qFindBlockEnclosureChainEnd;
    
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
        
        qSelectAffectedBlocks = db.prepare(`
            SELECT blockHash
            FROM blocks
            WHERE prevIncludedBlockHash IS NULL
            AND 
            (
                blockNum = :blockNum - 1
                OR
                (
                    blockNum = :blockNum
                    AND prevFilledBlockHash = :prevFilledBlockHash
                )
            )
        `);
        
        qCalcBlockEnclosureChainHash = db.prepare(`
            WITH RECURSIVE r(blockHash, prevIncludedBlockHash, proofOfWork) AS
            (
                SELECT b.blockHash, b.prevIncludedBlockHash, b.proofOfWork
                FROM blocks b
                WHERE blockHash = :blockHash
                
                UNION ALL
                
                SELECT b.blockHash, b.prevIncludedBlockHash, b.proofOfWork
                FROM blocks b
                JOIN r ON b.prevIncludedBlockHash = r.blockHash
            )
            
            SELECT
                hashFunc(proofOfWork) as blockHash,
                (SELECT blockHash FROM r ORDER BY rowid DESC LIMIT 1) AS prevIncludedBlockHash,
                (SELECT count(*) FROM r) AS recordsNum
            FROM (
                SELECT proofOfWork
                FROM r
                UNION ALL
                SELECT :proofOfWork AS proofOfWork
                ORDER BY proofOfWork
            ) orderedPoWs
            
        `);
        
        qFindBlockEnclosureChainEnd = db.prepare(`
            WITH RECURSIVE r(blockHash, prevIncludedBlockHash) AS
            (
                SELECT b.blockHash, b.prevIncludedBlockHash
                FROM blocks b
                WHERE blockHash = :blockHash
                
                UNION ALL
                
                SELECT b.blockHash, b.prevIncludedBlockHash
                FROM blocks b
                JOIN r ON b.prevIncludedBlockHash = r.blockHash
            )
            
            SELECT blockHash
            FROM r
            LIMIT 1
        `);
        
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
        
        qFindNextBlock = db.prepare(`
            SELECT blockNum, blockHash
            FROM blocks
            WHERE prevFilledBlockHash = :blockHash
            AND blockNum <= :limitBlockNum
            ORDER BY blockNum, recordsNum DESC
            LIMIT 1
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
            ),
            
            intersectFrom(blockHash, proofOfWork) AS
            (
                SELECT p.blockHash, proofOfWork
                FROM parallelBlocks p
                JOIN b USING(proofOfWork)
                WHERE b.blockHash = :fromBlockHash
            ),
            
            intersectNext(blockHash, proofOfWork) AS
            (
                SELECT blockHash, proofOfWork
                FROM parallelBlocks
                
                EXCEPT
                
                SELECT blockHash, proofOfWork
                FROM intersectFrom
                
                INTERSECT
                
                SELECT p.blockHash, proofOfWork
                FROM parallelBlocks p
                JOIN b USING(proofOfWork)
                WHERE b.blockHash = :nextBlockHash
            )
            
            SELECT blockHash, proofOfWork
            FROM intersectFrom
            
            INTERSECT
            
            SELECT blockHash, proofOfWork
            FROM intersectNext            
        `);
        
        qFindParallelBlocksWithoutNextBlock = db.prepare(`
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
            
            SELECT DISTINCT p.blockHash
            FROM parallelBlocks p
            JOIN b USING(proofOfWork)
            WHERE b.blockHash = :fromBlockHash
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
    
    void Insert(in Record r)
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
    
    void insertBlock(inout Block b)
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
    
    private BlockHash[] getAffectedBlocksChainsStarts(inout ref Record r)
    {
        alias q = qSelectAffectedBlocks;
        
        q.bind(":blockNum", r.blockNum);
        q.bind(":prevFilledBlockHash", r.prevFilledBlock);
        
        auto answer = q.execute();
        
        BlockHash[] res;
        
        foreach(a; answer)
            res ~= (a["blockHash"].as!(ubyte[]))[0..BlockHash.length];
        
        return res;
    }
    
    private Block calcBlockEnclosureChainHash(in BlockHash blockHash, in PoW pow)
    {
        alias q = qCalcBlockEnclosureChainHash;
        
        q.bind(":blockHash", blockHash);
        q.bind(":proofOfWork", pow.getUbytes);
        
        auto answer = q.execute();
        auto r = answer.front();
        
        Block res;
        
        res.blockHash = (r["blockHash"].as!(ubyte[]))[0..BlockHash.length];
        res.prevIncludedBlockHash = (r["prevIncludedBlockHash"].as!(ubyte[]))[0..BlockHash.length];
        res.recordsNum = r["recordsNum"].as!size_t;
        
        version(assert) answer.popFront;
        assert(answer.empty);
        
        return res;
    }
    
    private bool findNextBlock(
        in BlockHash blockHash,
        in size_t limitBlockNum,
        ref BlockHash blockHashRes,
        ref size_t blockNumRes
    )
    {
        alias q = qFindNextBlock;
        
        q.bind(":blockHash", blockHash);
        q.bind(":limitBlockNum", limitBlockNum);
        
        auto answer = q.execute();
        
        if(!answer.empty)
        {
            auto r = answer.front();
            
            blockNumRes = r["blockNum"].as!size_t;
            blockHashRes = (r["blockHash"].as!(ubyte[]))[0..BlockHash.length];
            
            version(assert) answer.popFront;
            assert(answer.empty);
            
            q.reset();
            return true;
        }
        
        q.reset();
        return false;
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
    
    /// For parallel blocks between two another
    private BlockHash[] findParallelBlocks
    (
        in BlockHash fromBlockHash,
        in BlockHash nextBlockHash,
        in size_t parallelBlockNum
    )
    {
        alias q = qFindParallelBlocks;
        
        q.bind(":fromBlockHash", fromBlockHash);
        q.bind(":nextBlockHash", fromBlockHash);
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
    
    private BlockHash[] findParallelBlocks
    (
        in BlockHash fromBlockHash,
        in size_t parallelBlockNum
    )
    {
        alias q = qFindParallelBlocksWithoutNextBlock;
        
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
    
    private BlockHash findBlockEnclosureChainEnd(in BlockHash from)
    {
        alias q = qFindBlockEnclosureChainEnd;
        
        q.bind(":blockHash", from);
        
        auto answer = q.execute();
        auto r = answer.front();
        
        BlockHash res = (r["blockHash"].as!(ubyte[]))[0..BlockHash.length];
        
        version(assert) answer.popFront;
        assert(answer.empty);
        
        q.reset();
        
        return res;
    }
    
    private struct Weight
    {
        size_t nodesNum;
        BlockHash blockHash;
    }
    
    private Weight findRecursively(in Block from, in size_t limitBlockNum, in Weight weight)
    {
        const nextBlocks = findNextBlocks(from.blockHash, limitBlockNum);
        Block[] toProcess;
        
        foreach(ref nb; nextBlocks)
        {
            toProcess ~= nb;
            
            // There also can be a parallel blocks
            const parallelBlocks = findParallelBlocks(
                from.blockHash,
                from.blockNum + 1
            );
            
            foreach(ref h; parallelBlocks)
                toProcess ~= getBlock(h);
        }
        
        // Path finding
        if(toProcess.length == 0)
        {
            // Current block is a leaf
            return weight;
        }
        else
        {
            Weight[] res = new Weight[toProcess.length];
            
            foreach(size_t i, ref b; toProcess)
            {
                const Weight currWeight = {
                    nodesNum: weight.nodesNum + 1,
                    blockHash: b.blockHash
                };
                
                res[i] = findRecursively(b, limitBlockNum, currWeight);
            }
            
            size_t maxKey;
            
            foreach(size_t i, ref w; res)
                if(w.nodesNum >= res[maxKey].nodesNum) maxKey = i;
            
            return res[maxKey];
        }
    }
    
    BlockHash findLatestHonestBlock(in Block from, in size_t limitBlockNum)
    {
        const Weight currWeight = {
            blockHash: from.blockHash
        };
        
        return findRecursively(from, limitBlockNum, currWeight).blockHash;
    }
}

unittest
{
    auto s = new Storage("_unittest_storage.sqlite");
    
    BlockHash prevFilledBlock;
    prevFilledBlock[0] = 88;
    
    Record r = {
        chainType: ChainType.Test,
        payloadType: PayloadType.Test,
        payload: [0x76, 0x76, 0x76, 0x76],
        blockNum: 1,
        prevFilledBlock: prevFilledBlock
    };
    
    r.proofOfWork.hash[0] = 1;
    s.Insert(r);
    r.proofOfWork.hash[0] = 2;
    s.Insert(r);
    r.proofOfWork.hash[0] = 3;
    s.Insert(r);
    
    Storage.Block b;
    b.blockHash[0] = 77;
    b.blockNum = 1;
    b.recordsNum = 1;
    b.prevFilledBlockHash = prevFilledBlock;
    s.insertBlock(b);
    assert(s.getBlock(b.blockHash) == b);
    
    Storage.Block b2;
    b2.prevIncludedBlockHash = b.blockHash;
    b2.blockHash[0] = 111;
    b2.blockNum = 1;
    b2.recordsNum = 2;
    b2.prevFilledBlockHash = prevFilledBlock;
    s.insertBlock(b2);
    
    Storage.Block b3; // parallel block between b2 and b4
    b3.blockHash[0] = 222;
    b3.blockNum = 2;
    b3.recordsNum = 1;
    b3.prevFilledBlockHash = prevFilledBlock;
    s.insertBlock(b3);
    
    Storage.Block b4; // next block from b2
    b4.blockHash[0] = 223;
    b4.blockNum = 3;
    b4.recordsNum = 1;
    b4.prevFilledBlockHash = b2.blockHash;
    s.insertBlock(b4);
    
    auto aff = s.getAffectedBlocksChainsStarts(r);
    
    assert(aff.length == 1);
    assert(aff[0][0] == 77);
    
    PoW pow;
    auto enc = s.calcBlockEnclosureChainHash(aff[0], pow);
    assert(enc.recordsNum == 2);
    
    BlockHash fNBlockHash;
    size_t fNBlockNum;
    auto fN = s.findNextBlock(prevFilledBlock, 1, fNBlockHash, fNBlockNum);
    assert(fN);
    assert(fNBlockNum == 1);
    assert(fNBlockHash == b2.blockHash);
    
    immutable latest1 = s.findLatestHonestBlock(b, 3);
    assert(latest1 == b.blockHash);
    
    immutable latest2 = s.findLatestHonestBlock(b2, 1);
    assert(latest2 == b2.blockHash);
    
    const blocks = s.findNextBlocks(prevFilledBlock, 8);
    assert(blocks.length == 3);
    
    const parallel = s.findParallelBlocks(b.blockHash, b2.blockHash, 1);
    assert(parallel.length == 0);
    
    /*
    uint early, later;
    s.calcPreviousRecordsNum(b.blockHash, early, later);
    
    assert(early == 0);
    assert(later == 3);
    */
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
