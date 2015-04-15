@trusted:

import d2sqlite3;
import config;

import std.exception: enforce;
import std.path: expandTilde;
import std.file;
import core.stdc.errno;
import std.datetime;
import std.typecons: Nullable;


immutable string sqlCreateSchema =
`CREATE TABLE IF NOT EXISTS Peers (
    addr TEXT NOT NULL PRIMARY KEY,
    type INT NOT NULL DEFAULT 0,
    lastSeen INT NOT NULL,
    banned INT NOT NULL
);
`;

private struct Peer
{
    string addr;
    ubyte type = 0;
}

class PeersStorage
{
    const string path;
    Database db;
    
    private Statement
        qInsertPeer,
        qSelectRandomPeer;
    
    this(in string filename)
    {
        const appdir = expandTilde(cfg.storageDir);
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
                type,
                lastSeen,
                banned
            )
            VALUES (
                :addr,
                :type,
                :lastSeen,
                :banned
            )
        ");
        
        qSelectRandomPeer = db.prepare("
            SELECT addr, type
            FROM Peers
            WHERE lastSeen >= :lastSeenLimit
            AND NOT banned
            ORDER BY RANDOM()
            LIMIT 1;
        ");
    }
    
    private void insertOrUpdatePeer(in Peer peer, in bool banned = false)
    {
        alias e = qInsertPeer;
        
        e.bind(":addr", peer.addr);
        e.bind(":type", peer.type);
        e.bind(":lastSeen", Clock.currTime.toUnixTime);
        e.bind(":banned", banned);
        
        e.execute();
        assert(db.changes() == 1);
        e.reset();
    }
    
    private Nullable!Peer getRandomPeer()
    {
        alias q = qSelectRandomPeer;
        
        q.bind(":lastSeenLimit", Clock.currTime.toUnixTime - 60 * 60 * 24 * 90 /* 90 days */);
        
        auto answer = q.execute();
        
        Nullable!Peer nullableResult;
        
        if(!answer.empty)
        {
            auto r = answer.front();
            
            Peer res;
            res.addr = r["addr"].as!string;
            res.type = r["type"].as!ubyte;
                        
            nullableResult = res;
            
            version(assert) answer.popFront;
            assert(answer.empty);
        }
        
        q.reset();
        
        return nullableResult;
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
    
    Peer p;
    p.addr = "1.2.3.4";
    
    s.insertOrUpdatePeer(p);
    s.insertOrUpdatePeer(p);
    
    auto peer = s.getRandomPeer();
    assert(peer.addr == "1.2.3.4");
    
    s.purge;
}
