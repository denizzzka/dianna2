@trusted:

import deimos.openssl.evp;
import deimos.openssl.ecdsa;
import deimos.openssl.pem;

import std.exception: enforce;
import std.stdio: File;
import std.file: setAttributes;
import std.path: expandTilde;
import std.conv: octal;


struct Key
{
    ubyte[30] key;
    alias key this;
    
    string name;
}

alias signature = ECDSA_SIG;

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

void createKey(in string name)
{
    const filename = expandTilde("~/.dianna2/key_"~name~".pem");
    auto file = File(filename, "w");
    setAttributes(filename, octal!"600"); // chmod 600
    
    auto key = generatePrivateKey();
    
    const res = PEM_write_PrivateKey(file.getFP, key, null, null, 0, null, null);
    
    enforce(res == 1, "PEM_write_PrivateKey error");
    
    scope(exit) EVP_PKEY_free(key);
    
    file.close();
}

unittest
{
    import std.file: remove;
    
    immutable key_name = "_unittest_key";
    
    createKey(key_name);
    
    remove(expandTilde("~/.dianna2/key_"~key_name~".pem"));
}
