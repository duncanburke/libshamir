#ifndef _SHAMIR_H
#define _SHAMIR_H

#include <unistd.h>

typedef uint8_t gf256;

typedef struct {
	size_t size;
	unsigned threshold;
} shamir_params_t;


typedef gf256 *shamir_poly_t;
typedef gf256 *shamir_key_t;

/* 
	 shamir_param_t params = {size = sizeof(secret),
	                          threshold = 2};
	 size_t key_size = shamir_key_size(params);

	 shamir_poly_t p = malloc(shamir_poly_size(params));
	 void* keys = calloc(N_KEYS, key_size);

	 shamir_init_poly(params, p, secret);
	 
	 shamir_get_keys(params, p, keys, N_KEYS);

	 
	 
 */

ssize_t shamir_poly_size(shamir_params_t params);
ssize_t shamir_key_size(shamir_params_t params);

int shamir_init_poly(shamir_params_t params, shamir_poly_t p, uint8_t *secret);
int _shamir_get_key(shamir_params_t params, shamir_poly_t p, gf256 x, _shamir_key_t *key);
int shamir_get_keys(shamir_params_t params, shamir_poly_t p, void *keys, unsigned nkeys);

int shamir_recover_secret(shamir_params_t params, void *keys, uint8_t *secret);

#endif


