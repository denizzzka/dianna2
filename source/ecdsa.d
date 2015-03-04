@trusted:

import deimos.openssl.evp;
import deimos.openssl.ec: point_conversion_form_t;
import deimos.openssl.ecdsa;
import deimos.openssl.pem;

import std.exception: enforce;
import std.stdio: File;
import std.file: exists, setAttributes;
import std.path: expandTilde;
import std.conv: octal, to;


struct Key
{
    ubyte[30] key;
    alias key this;
    
    string name;
}

alias PubKey = ubyte[33];

struct Signature
{
    alias ECSign = ubyte[72];
    
    ECSign sign;
    ubyte slen;
    PubKey pubKey;
    
    ubyte[] serialize() const
    {
        ubyte[] res;
        
        res ~= sign;
        res ~= pubKey;
        
        return res;
    }
    
    static Signature deserialize(in ubyte[] from)
    in
    {
        assert(from.length == sign.length + pubKey.length);
    }
    body
    {
        Signature res;
        
        res.sign = from[0..sign.length];
        res.pubKey = from[sign.length..sign.length + pubKey.length];
        
        return res;
    }
}

unittest
{
    Signature s1;
    
    s1.sign[0] = 0xEE;
    s1.pubKey[0] = 0xAA;
    
    const ser = s1.serialize();
    
    Signature s2 = Signature.deserialize(ser);
    
    assert(s1 == s2);
}

private EVP_PKEY* generatePrivateKey()
{
    EVP_PKEY_CTX* pctx;
    EVP_PKEY_CTX* kctx;
    EVP_PKEY* params;
    EVP_PKEY* key;
    
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, null);
    enforce(pctx);
    
    enforce(EVP_PKEY_paramgen_init(pctx));
    
    enforce(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp256k1));
    
    enforce(EVP_PKEY_paramgen(pctx, &params));
    
    kctx = EVP_PKEY_CTX_new(params, null);
    enforce(kctx);
    
    enforce(EVP_PKEY_keygen_init(kctx));
    
    enforce(EVP_PKEY_keygen(kctx, &key));
    
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
    
    EVP_PKEY* key = generatePrivateKey();
    
    const res = PEM_write_PrivateKey(file.getFP, key, null, null, 0, null, null);
    
    enforce(res == 1, "PEM_write_PrivateKey error");
    
    scope(exit) EVP_PKEY_free(key);
    
    file.close();
}

private EVP_PKEY* readKey(in string keyfilePath)
{
    auto file = File(keyfilePath, "r");
    
    EVP_PKEY* res = PEM_read_PrivateKey(file.getFP, null, null, null);
    
    file.close();
    
    enforce(res != null);
    
    return res;
}

private PubKey getPubKey(in EC_KEY* ec_key)
{
    const EC_GROUP* ec_group = EC_KEY_get0_group(ec_key);
    enforce(ec_group);
    
    const EC_POINT* ec_point = EC_KEY_get0_public_key(ec_key);
    enforce(ec_point);
    
    PubKey res;
    
    const len = EC_POINT_point2oct(
        ec_group,
        ec_point,
        point_conversion_form_t.POINT_CONVERSION_COMPRESSED,
        res.ptr,
        PubKey.length,
        null
    );
    enforce(len > 0);
    enforce(len == PubKey.length, "Public key size mismatch");
    
    scope(exit)
    {
        // FIXME:
        //if(ec_key) EC_KEY_free(ec_key);
        //if(ec_group) EC_KEY_free(ec_group);
        //if(ec_point) EC_POINT_free(ec_point);
    }
    
    return res;
}

private EC_KEY* extractEC_KEY(in PubKey pubKey)
{
    EC_KEY* ec_key;
    EC_POINT* ec_point;
    
    ec_key = enforce(EC_KEY_new_by_curve_name(NID_secp256k1));
    const ec_group = enforce(EC_KEY_get0_group(ec_key));
    ec_point = enforce(EC_POINT_new(ec_group));
    
    enforce(EC_POINT_oct2point(ec_group, ec_point, pubKey.ptr, pubKey.length, null) == 1);
    
    enforce(EC_KEY_set_public_key(ec_key, ec_point) == 1);
    
    // FIXME: memory leak?
    
    return ec_key;
}

Signature sign(in ubyte[] digest, in string keyfilePath)
{
    auto key = readKey(keyfilePath);
    
    EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(key);
    enforce(ec_key);
    
    enforce(ECDSA_size(ec_key) == Signature.sign.length);
    
    const ECDSA_SIG* ecdsa_sig = ECDSA_do_sign(digest.ptr, to!int(digest.length), ec_key);
    enforce(ecdsa_sig);
    
    Signature res;
    res.pubKey = getPubKey(ec_key);
    
    auto p = res.sign.ptr;
    res.slen = to!ubyte(enforce(i2d_ECDSA_SIG(ecdsa_sig, &p)));
    enforce(res.slen <= Signature.sign.length);
    
    scope(exit)
    {
        // FIXME: memory leak?
        //if(ctx) EVP_PKEY_CTX_free(ctx);
        //if(key) EVP_PKEY_free(key);
    }
    
    return res;
}

bool verify(in ubyte[] digest, in Signature sig)
{
    EC_KEY* pubKey = extractEC_KEY(sig.pubKey);
    
    auto sptr = sig.sign.ptr;
    
    ECDSA_SIG* ecdsa_sig;
    if(!d2i_ECDSA_SIG(&ecdsa_sig, &sptr, sig.slen)) return false;
    
    return ECDSA_do_verify(digest.ptr, to!int(digest.length), ecdsa_sig, pubKey) == 1;
    
    scope(exit)
    {
        // FIXME: memory leak?
        //if(ctx) EVP_PKEY_CTX_free(ctx);
        //if(key) EVP_PKEY_free(key);
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
    
    foreach(ref c; s.sign) c = 0x00; // broke signature
    
    assert(!verify(digest, s));
    
    remove(path);
}
