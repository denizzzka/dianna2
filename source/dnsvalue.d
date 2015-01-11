@safe:


struct Signature
{
    private ubyte[10] signature;
    
    alias signature this;
}

struct DNSValue
{
    Signature signature;
    
    string A = "A record blah blah blah";
}
