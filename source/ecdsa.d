@trusted:

import deimos.openssl.ec: NID_secp256k1;
import deimos.openssl.ecdsa;


struct Key
{
    typeof(EC_KEY_new_by_curve_name(NID_secp256k1)) key;
    alias key this;
    
    string name;
}

alias signature = ECDSA_SIG;

Key newKey(in string name)
{
    Key r;
    r.name = name;
    r = EC_KEY_new_by_curve_name(NID_secp256k1);
    
    return r;
}

unittest
{
    auto key = newKey("test key");
}
