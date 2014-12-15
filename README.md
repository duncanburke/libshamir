# libshamir [![Build Status](https://travis-ci.org/duncanburke/libshamir.svg?branch=master)](https://travis-ci.org/duncanburke/libshamir)

An implementation of Shamir's Secret Sharing in GF(256) with an emphasis on simplicity and readability.

libshamir is based on [libgfshare](http://www.digital-scurf.org/software/libgfshare). Though almost no code is shared, I consider this a derivative work and have given attribution to Daniel Silverstone, Simon McVittie and Mark D. Wooding.

# Building

libshamir requires a C99 compiler, toolchain and unix-like exposing `/dev/urandom`, `/dev/arandom` or `dev/random`.

~~~ {.bash}
git clone https://github.com/duncanburke/libshamir.git
cd libshamir
autoreconf -i
./configure
make
make check
make install
~~~

# Documentation

Full documentation is provided in included man pages.

# Example

~~~ {.C}
#define N_KEYS 3
char secret[] = "hello, world";
shamir_params_t params = {.size = sizeof(secret), .threshold = 2};

ssize_t poly_size = shamir_poly_size(params);
ssize_t key_size = shamir_key_size(params);

shamir_poly_t *p = malloc(poly_size);
shamir_key_t *k = malloc(N_KEYS*key_size);

shamir_init_poly(params, p, secret);
shamir_get_keys(params, p, k, N_KEYS);

/* 3 distinct keys have been generated */
shamir_key_t *k1 = k;
shamir_key_t *k2 = k + key_size;
shamir_key_t *k3 = k + 2*key_size;

/* Recover the secret using just 2 keys */
shamir_key_t *_k = malloc(2*key_size);
uint8_t _secret = malloc(params.size);
memcpy(_k, k3, key_size);
memcpy(_k, k1, key_size);

shamir_recover_secret(params, _k, _secret);
assert(memcmp(secret, _secret, params.size) == 0);

/* Recover the polynomial from 2 keys */
memset(p, 0, poly_size);
shamir_recover_poly(params, _k, p);

/* Create another key. We need to manually
   specify its 'x' value, so find the first
   unused value.
*/
gf256_t max_x = 0;
for (int i = 0; i < N_KEYS; i++){
    gf256 x = shamir_key_x(k + i*key_size);
    max_x = (x > max_x) ? x : max_x;
}
shamir_key_t *k4 = malloc(key_size);
shamir_get_key(params, p, max_x + 1, k4);
~~~
