@trusted:

import deimos.openssl.evp;
import deimos.openssl.ecdsa;
import deimos.openssl.pem;

import std.exception: enforce;
import std.stdio: File;
import std.file: exists, setAttributes;
import std.path: expandTilde;
import std.conv: octal;


struct Key
{
    ubyte[30] key;
    alias key this;
    
    string name;
}

alias signature = ubyte[72];

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

void createKey(in string keyfilePath)
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

signature sign(in ubyte[] digest, in string keyfilePath)
{
    auto key = readKey(keyfilePath);
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, null);
    enforce(ctx);
    
    enforce(EVP_PKEY_sign_init(ctx) == 1);
    
    size_t siglen;
    
    // obtain signature length
    enforce(EVP_PKEY_sign(ctx, null, &siglen, digest.ptr, digest.length) == 1);
    
    // ecdsa signature size check
    enforce(siglen == signature.length);
    
    signature res;
    
    // sign
    enforce(EVP_PKEY_sign(ctx, res.ptr, &siglen, digest.ptr, digest.length) == 1);
    
    scope(exit)
    {
        if(ctx) EVP_PKEY_CTX_free(ctx);
        if(ctx) EVP_PKEY_free(key);
    }
    
    return res;
}

bool verify(in ubyte[] digest, in signature sig, in string keyfilePath)
{
    auto key = readKey(keyfilePath);
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, null);
    enforce(ctx);
    
    enforce(EVP_PKEY_verify_init(ctx) == 1);
    
    auto res = EVP_PKEY_verify(ctx, sig.ptr, sig.length, digest.ptr, digest.length);
    
    scope(exit)
    {
        if(ctx) EVP_PKEY_CTX_free(ctx);
        if(ctx) EVP_PKEY_free(key);
    }
    
    return res == 1;
}

unittest
{
    import std.file: remove;
    
    immutable path = "/tmp/_unittest_key.pem";
    
    createKey(path);
    
    assert(readKey(path));
    
    ubyte[20] digest;
    
    auto s = sign(digest, path);
    
    assert(verify(digest, s, path));
    
    foreach(ref c; s) c = 0x00; // broke signature
    
    assert(!verify(digest, s, path));
    
    remove(path);
}
