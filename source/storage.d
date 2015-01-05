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
    prev_filled_block_hour INT, -- UTC
    proof_of_work BLOB
);

CREATE TABLE blocks (
    hour INT,
    hash BLOB
);
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
}

unittest
{
    auto storage = new Storage("_unittest.sqlite");
    storage.Remove;
}
