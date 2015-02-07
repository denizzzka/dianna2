@trusted:

import deimos.openssl.evp;
import deimos.openssl.ecdsa;

import std.exception: enforce;


struct Key
{
    ubyte[30] key;
    alias key this;
    
    string name;
}

alias signature = ECDSA_SIG;

Key newKey(in string name)
{
    Key res;
    res.name = name;
    //res.key = EC_KEY_new_by_curve_name(NID_secp256k1);
    
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
    
    // FIXME: need exit scope
    if(pctx) EVP_PKEY_CTX_free(pctx);
    if(kctx) EVP_PKEY_CTX_free(kctx);
    if(params) EVP_PKEY_free(params);
    
    return res;
}

unittest
{
    auto key = newKey("test key");
}
