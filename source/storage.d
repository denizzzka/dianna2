import d2sqlite3;

import std.process: environment;
import std.file;

immutable string sqlCreateSchema =
`CREATE TABLE IF NOT EXISTS sqlar (
    name TEXT PRIMARY KEY,
    mode INT,
    mtime INT,
    sz INT,
    data BLOB
);`;

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
        {
            mkdir(appdir);
        }
        catch(Exception e){}
        
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
    auto storage = new Storage("unittest.sqlite");
    storage.Remove;
}
