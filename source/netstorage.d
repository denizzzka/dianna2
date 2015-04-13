@trusted:

import d2sqlite3;
import config;

import std.exception: enforce;
import std.path: expandTilde;
version(unittest) import std.file;
import core.stdc.errno;
import std.datetime;
//import std.conv: to;
//import std.typecons: Nullable;


immutable string sqlCreateSchema =
`CREATE TABLE IF NOT EXISTS Peers (
    addr TEXT NOT NULL PRIMARY KEY,
    type INT NOT NULL DEFAULT 0,
    lastSeen INT NOT NULL
);
`;

class PeersStorage
{
    const string path;
    Database db;
    
    private Statement
        qInsertPeer;
    
    this(in string filename)
    {
        const appdir = expandTilde(cfg.storage_path);
        path = appdir~"/"~filename;
        
        try
            mkdir(appdir);
        catch(FileException e)
            if(e.errno != EEXIST) throw e;
        
        db = Database(path);
        
        db.run(sqlCreateSchema);
        
        qInsertPeer = db.prepare("
            INSERT OR REPLACE INTO Peers (
                addr,
                lastSeen
            )
            VALUES (
                :addr,
                :lastSeen
            )
        ");
    }
    
    private void insertOrUpdatePeer(in string peer)
    {
        alias e = qInsertPeer;
        
        e.bind(":addr", peer);
        e.bind(":lastSeen", Clock.currTime.toUnixTime);
        
        e.execute();
        assert(db.changes() == 1);
        e.reset();
    }
    
    version(unittest)
    void purge()
    {
        remove(path);
    }
}

unittest
{
    auto s = new PeersStorage("_unittest_peers.sqlite");
    
    s.insertOrUpdatePeer("1.2.3.4");
    s.insertOrUpdatePeer("1.2.3.4");
    
    s.purge;
}
