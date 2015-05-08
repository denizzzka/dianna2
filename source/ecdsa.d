@trusted:

import protobuf;

import deimos.openssl.evp;
import deimos.openssl.ec: point_conversion_form_t;
import deimos.openssl.ecdsa;
import deimos.openssl.pem;
import deimos.openssl.err;

import std.exception: Exception, enforce, enforceEx;
import std.stdio: File;
import std.file: exists, setAttributes;
import std.path: expandTilde;
import std.conv: octal, to;


alias PubKey = ubyte[33];

struct Signature
{
    alias ECSign = ubyte[72];
    
    ECDSASignature pb;
    alias pb this;
    
    PubKey pubKey() { return pb.pubKey[0..PubKey.length]; }
    PubKey pubKey(PubKey pk) { pb.pubKey = pk.dup; return pk; }
}

unittest
{
    Signature s1;
    Signature.ECSign es;
    PubKey pk;
    
    es[0] = 0xEE;
    pk[0] = 0xAA;
    
    s1.signature = es;
    s1.pubKey = pk;
    
    auto ser = s1.serialize();
    
    Signature s2;
    s2.deserialize(ser);
    
    assert(s1.signature == s2.signature);
}

class OpenSSLEx : Exception
{
    struct Errors
    {
        string file;
        size_t line;
        string msg;
    }
    
    Errors[] errList;
    
    this(string msg, string fileEx, const size_t lineEx)
    {
        ERR_load_crypto_strings();
        
        const (char)* file;
        int line;
        
        long errCode;
        
        do{
            errCode = ERR_get_error_line(&file, &line);
            
            if(errCode)
            {
                Errors e;
                e.file = to!string(file);
                e.line = line;
                e.msg = to!string(ERR_error_string(errCode, null));
                
                errList ~= e;
            }
        }
        while(errCode);
        
        ERR_free_strings();
        
        enforce(errList.length > 0);
        
        msg ~= "\nOpenSSL error stack:\n";
        foreach_reverse(i, e; errList)
            msg ~= "("~to!string(i)~")"~
                (
                    e.msg.length > 0 ?
                        " Msg:\""~e.msg~"\"" :
                        " No message"
                )~
                ",file:"~e.file~
                ",line:"~to!string(e.line)~
                "\n";
        
        super(msg, fileEx, lineEx);
    }
}

private EVP_PKEY* generateKeyPair()
{
    EVP_PKEY_CTX* pctx;
    EVP_PKEY_CTX* kctx;
    EVP_PKEY* params;
    EVP_PKEY* key;
    
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, null);
    enforceEx!OpenSSLEx(pctx);
    
    enforceEx!OpenSSLEx(EVP_PKEY_paramgen_init(pctx));
    
    enforceEx!OpenSSLEx(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp256k1));
    
    enforceEx!OpenSSLEx(EVP_PKEY_paramgen(pctx, &params));
    
    kctx = enforceEx!OpenSSLEx(EVP_PKEY_CTX_new(params, null));
    
    enforceEx!OpenSSLEx(EVP_PKEY_keygen_init(kctx));
    
    enforceEx!OpenSSLEx(EVP_PKEY_keygen(kctx, &key));
    
    scope(exit)
    {
        if(pctx) EVP_PKEY_CTX_free(pctx);
        if(kctx) EVP_PKEY_CTX_free(kctx);
        if(params) EVP_PKEY_free(params);
    }
    
    return key;
}

void createKeyPair(in string keyfilePath)
{
    enforce(!exists(keyfilePath), "Key file already exists");
    
    auto file = File(keyfilePath, "w");
    setAttributes(keyfilePath, octal!"600"); // chmod 600
    
    EVP_PKEY* key = generateKeyPair();
    
    enforceEx!OpenSSLEx(
        PEM_write_PrivateKey(file.getFP, key, null, null, 0, null, null) == 1,
        "PEM_write_PrivateKey error"
    );
    
    EVP_PKEY_free(key);
    
    scope(exit) file.close();
}

private EVP_PKEY* readKey(in string keyfilePath)
{
    auto file = File(keyfilePath, "r");
    
    EVP_PKEY* res = enforceEx!OpenSSLEx(PEM_read_PrivateKey(file.getFP, null, null, null));
    
    scope(exit) file.close();
    
    return res;
}

private PubKey getPubKey(scope EC_KEY* ec_key)
{
    const EC_GROUP* ec_group = enforceEx!OpenSSLEx(EC_KEY_get0_group(ec_key));
    const EC_POINT* ec_point = enforceEx!OpenSSLEx(EC_KEY_get0_public_key(ec_key));
    
    PubKey res;
    
    const len = EC_POINT_point2oct(
        ec_group,
        ec_point,
        point_conversion_form_t.POINT_CONVERSION_COMPRESSED,
        res.ptr,
        PubKey.length,
        null
    );
    enforceEx!OpenSSLEx(len > 0);
    enforce(len == PubKey.length, "Public key size mismatch");
    
    return res;
}

private EC_KEY* extractEC_KEY(in PubKey pubKey)
{
    EC_KEY* ec_key;
    EC_POINT* ec_point;
    
    ec_key = enforceEx!OpenSSLEx(EC_KEY_new_by_curve_name(NID_secp256k1));
    
    enforce(Signature.ECSign.length == ECDSA_size(ec_key));
    
    try
    {
        const ec_group = enforceEx!OpenSSLEx(EC_KEY_get0_group(ec_key));
        ec_point = enforceEx!OpenSSLEx(EC_POINT_new(ec_group));
        
        enforceEx!OpenSSLEx(EC_POINT_oct2point(ec_group, ec_point, pubKey.ptr, pubKey.length, null) == 1);
        enforceEx!OpenSSLEx(EC_KEY_set_public_key(ec_key, ec_point) == 1);
    }
    catch(Exception e)
    {
        EC_KEY_free(ec_key);
        
        throw e;
    }
    finally
    {
        if(ec_point) EC_POINT_free(ec_point);
    }
    
    return ec_key;
}

Signature sign(in ubyte[] digest, in string keyfilePath)
{
    auto key = readKey(keyfilePath);
    
    EC_KEY* ec_key = enforceEx!OpenSSLEx(EVP_PKEY_get1_EC_KEY(key));
    
    ECDSA_SIG* ecdsa_sig = ECDSA_do_sign(digest.ptr, to!int(digest.length), ec_key);
    enforceEx!OpenSSLEx(ecdsa_sig);
    
    Signature res;
    res.pubKey = getPubKey(ec_key);
    
    Signature.ECSign buf;
    
    auto p = buf.ptr;
    const len = to!ubyte(enforceEx!OpenSSLEx(i2d_ECDSA_SIG(ecdsa_sig, &p)));
    enforce(len <= buf.length);
    
    res.signature = buf[0..len].dup;
    
    scope(exit)
    {
        if(key) EVP_PKEY_free(key);
        if(ecdsa_sig) ECDSA_SIG_free(ecdsa_sig);
    }
    
    return res;
}

bool verify(in ubyte[] digest, Signature sig)
{
    EC_KEY* pubKey;
    ECDSA_SIG* ecdsa_sig;
    
    auto orig = sig.signature.dup;
    const (ubyte)* sptr = orig.ptr;
    
    try
    {
        pubKey = extractEC_KEY(sig.pubKey);
        
        if(!d2i_ECDSA_SIG(&ecdsa_sig, &sptr, orig.length)) return false;
        
        return ECDSA_do_verify(digest.ptr, to!int(digest.length), ecdsa_sig, pubKey) == 1;
    }
    catch(OpenSSLEx)
    {
        return false; // Any errors also indicate that signature is invalid
    }
    finally
    {
        if(pubKey) EC_KEY_free(pubKey);
        if(ecdsa_sig) ECDSA_SIG_free(ecdsa_sig);
    }
}

unittest
{
    import std.file: remove;
    
    immutable path = "/tmp/_unittest_key.pem";
    
    createKeyPair(path);
    
    assert(readKey(path));
    
    ubyte[20] digest;
    
    auto s = sign(digest, path);
    
    assert(verify(digest, s));
    
    Signature.ECSign buf;
    s.signature = buf; // just brokes signature
    
    assert(!verify(digest, s));
    
    remove(path);
    
    const PubKey invalidKey;
    bool exFlag = false;
    try
        extractEC_KEY(invalidKey);
    catch(OpenSSLEx)
        exFlag = true;
    finally
        assert(exFlag);
}
