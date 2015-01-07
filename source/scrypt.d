@safe:

import std.exception: enforce;


enum SCRYPT_N = 16384;
enum SCRYPT_r = 8;
enum SCRYPT_p = 16;

void calcScrypt(T)(
    out T result,
    const ubyte[] src,
    const ubyte[] salt,
    uint N = SCRYPT_N,
    uint r = SCRYPT_r,
    uint p = SCRYPT_p,
    size_t outputBuf = 64
) pure
{
    auto errno = libscrypt_scrypt(
        src.ptr,
        src.length,
        salt.ptr,
        salt.length,
        N,
        r,
        p,
        result.ptr,
        result.length
    );
    
    enforce(!errno, "Error in scrypt function");
}

void genSalt(T)(out T res) pure @nogc
{
    libscrypt_salt_gen(res.ptr, res.length);
}

unittest
{
    ubyte[8] r;
    calcScrypt(r, [0x11, 0x22, 0x33, 0x44], [0x11, 0x22, 0x33, 0x44]);
    
    genSalt(r);
}

private:

alias ubyte uint8_t;
alias ulong uint64_t;
alias uint uint32_t;

@trusted:
extern (C):
    
/**
 * libscrypt_scrypt(passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen):
 * password; duh
 * N: CPU AND RAM cost (first modifier)
 * r: RAM Cost
 * p: CPU cost (parallelisation)
 * 
 * The parameters r, p, and buflen
 * must satisfy r * p < 2^30 and buflen <= (2^32 - 1) * 32.  The parameter N
 * must be a power of 2 greater than 1.
 *
 * In short, N is your main performance modifier. Values of r = 8, p = 1 are
 * standard unless you want to modify the CPU/RAM ratio.
 * Return 0 on success; or -1 on error.
 */
int libscrypt_scrypt(const uint8_t *, size_t, const uint8_t *, size_t, uint64_t,
    uint32_t, uint32_t, /*@out@*/ uint8_t *, size_t) pure @nogc;

/** Generates a salt.
 * This is not a cryptographically unpredictable function,
 * but should produce appropriately randomised output for this purpose
 */
void libscrypt_salt_gen(/*@out@*/ ubyte *rand, size_t len) pure @nogc;
