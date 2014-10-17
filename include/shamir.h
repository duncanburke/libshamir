#ifndef _SHAMIR_H
#define _SHAMIR_H

#include <stdint.h>
#include <unistd.h>

typedef uint8_t gf256_t;

typedef struct {
	size_t size;
	unsigned threshold;
} shamir_params_t;


typedef gf256_t shamir_poly_t;
typedef gf256_t shamir_key_t;

ssize_t shamir_poly_size(shamir_params_t params);
ssize_t shamir_key_size(shamir_params_t params);

int shamir_init_poly(shamir_params_t params, shamir_poly_t *p, uint8_t *secret);
int _shamir_get_key(shamir_params_t params, shamir_poly_t *p, gf256_t x, shamir_key_t *k);
int shamir_get_keys(shamir_params_t params, shamir_poly_t *p, shamir_key_t *k, unsigned n);

int shamir_recover_secret(shamir_params_t params, shamir_key_t *k, uint8_t *secret);

#endif


