import records;
import d2sqlite3;

import std.process: environment;
import std.file;
import core.stdc.errno;


immutable string sqlCreateSchema =
`CREATE TABLE IF NOT EXISTS records (
    version INT,
    chain INT, -- 0 = real chain, 1 = testing chain
    key BLOB,
    value BLOB,
    signature BLOB,
    prev_filled_block_num INT,
    proof_of_work BLOB
);

CREATE INDEX IF NOT EXISTS prev_block
ON records(prev_filled_block_num);

CREATE TABLE IF NOT EXISTS blocks (
    block_num INT,
    hash BLOB
);

CREATE INDEX IF NOT EXISTS block_num
ON blocks(block_num);
`;

class Storage
{
    const string path;
    Database db;
    
    this(string filename = "storage.sqlite3")
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
    }
    
    version(unittest)
    void Remove()
    {
        db.close();
        remove(path);
    }
    
    void Insert(Record r)
    {
        auto q = db.query("INSERT INTO records (version, chain, key, value)\n"
                          "VALUES (0, :chainType, :key, :value)");
                 
        q.bind(":chainType", r.chainType);
        q.bind(":key", r.key);
        q.bind(":value", r.value);
        
        q.execute();
    }
}

unittest
{
    auto s= new Storage("_unittest.sqlite");
    
    Record r = {
            chainType: ChainType.Test,
            key:[0xDE, 0xEA, 0xBE, 0xEF],
            value:[0x11, 0x22, 0x33, 0x44]
        };
        
    s.Insert(r);
    s.Insert(r);
    s.Insert(r);
    
    s.Remove;
}
