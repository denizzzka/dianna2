import d2sqlite3;

import std.exception;

class Storage
{
    this()
    {
        auto db = Database("testdb");
    }
}
