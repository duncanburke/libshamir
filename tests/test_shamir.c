#include "shamir.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#define debug(M, ...) fprintf(stderr, "DEBUG %s:%d: " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)

int fail(int _errno){
	errno = _errno;
	return -1;
}

int copy_idxs(size_t key_size, unsigned t, shamir_key_t *k, shamir_key_t *_k, unsigned *k_idxs){
	if (!k || !_k || !k_idxs)
		return fail(EINVAL);
	for (unsigned i = 0; i < t; i++){
		memcpy(_k + i*key_size, k + k_idxs[i]*key_size, key_size);
	}
	return 0;
}

int _shamir_next_combination(unsigned *idxs, unsigned a, unsigned b);

#define CHECK_FAIL(pred, err, label) if (pred) { saved_errno = (err); goto label; }

int _check_recovery(size_t size, unsigned n, unsigned t, int recover_poly){
	int ret;
	int saved_errno;
	int failure = 0;

	debug("size: %zd, n: %d, t: %d", size, n, t);

	shamir_params_t params = {.size = size, .t = t};
	if (n < t) return fail(EINVAL);

	ssize_t _poly_size = shamir_poly_size(params);
	if (_poly_size == -1) return -1;
	ssize_t _key_size = shamir_key_size(params);
	if (_key_size == -1) return -1;

	size_t poly_size = (size_t)_poly_size;
	size_t key_size = (size_t)_key_size;

	shamir_poly_t *p = malloc(2*poly_size);
	CHECK_FAIL(!p, ENOMEM, err1);
	shamir_poly_t *_p = p + poly_size;

	/* allocate space for all keys, and for a t-sized
		 array of a combination thereof */
	shamir_key_t *k = malloc((n+t) * key_size);
	CHECK_FAIL(!k, ENOMEM, err2);

	shamir_key_t *_k = k + n * key_size;

	/* indices for generating key combinations */
	unsigned *k_idxs = malloc(t * sizeof(unsigned));
	CHECK_FAIL(!k_idxs, ENOMEM, err3);

	/* allocate space for the secret and for the
		 recovered secret (which should match */
	uint8_t *secret = malloc(2*size);
	CHECK_FAIL(!secret, ENOMEM, err4);

	uint8_t *_secret = secret + size;

	/* Use the internal RNG to create a secret */
	ret = _shamir_init_random();
	CHECK_FAIL(ret == -1, errno, err5);

	ret = _shamir_get_random(secret, size);
	CHECK_FAIL(ret == -1, errno, err5);

	ret = _shamir_cleanup_random();
	CHECK_FAIL(ret == -1, errno, err5);

	/* Generate the polynomial, get the keys */
	ret = shamir_init_poly(params, p, secret);
	CHECK_FAIL(ret == -1, errno, err5);

	for (unsigned i = 0; i < t; i++){
		debug("c%d: %d", i, *(p+i));
	}

	ret = shamir_get_keys(params, p, k, n);
	CHECK_FAIL(ret == -1, errno, err5);

	/* Enumerate combinations of the keys, copy each combination
		 into _k, recover the secret and verify it matches the
		 original secret.
	*/

	for (unsigned i = 0; i < t; i++)
		k_idxs[i] = i;
	for (;;){
		ret = copy_idxs(key_size, t, k, _k, k_idxs);
		CHECK_FAIL(ret == -1, errno, err5);

		ret = shamir_recover_secret(params, _k, _secret);
		CHECK_FAIL(ret == -1, errno, err5);
		ret = memcmp(secret, _secret, size);
		if (ret) failure = 1;

		if (recover_poly){
			ret = shamir_recover_poly(params, _k, _p);
			CHECK_FAIL(ret == -1, errno, err5);
			ret = memcmp(p, _p, poly_size);
			if (ret) failure = 1;
		}

		if (failure){
			for (unsigned i = 0; i < t; i++)
				debug("(%d,%d)", *(_k + key_size*i), *(_k + key_size*i + 1));
			break;
		}

		ret = _shamir_next_combination(k_idxs, n, t);
		CHECK_FAIL(ret == -1, errno, err5);
		if (ret)
			break;
	}

	free(secret);
	free(k_idxs);
	free(k);
	free(p);
	return failure;

 err5:
	free(secret);
 err4:
	free(k_idxs);
 err3:
	free(k);
 err2:
	free(p);
 err1:
	return fail(saved_errno);
}

void check_recovery(size_t size, unsigned n, unsigned t, int recover_poly){
	int ret;
	char str[16];

	ret = _check_recovery(size, n, t, recover_poly);
	if (ret == -1){
		snprintf(str, sizeof(str), "n: %d t: %d", n, t);
		perror(str);
		abort();
	} else if (ret == 1){
		abort();
	}
}

int main (int argc, char **argv){
	check_recovery(1,2,2,1);
	check_recovery(4096,3,2,1);

	check_recovery(1,10,10,1);
	check_recovery(1,16,2,1);

	check_recovery(4096,255,255,0);


	for (unsigned t = 2; t < 254; t+=64)
		check_recovery(1,t+2,t,0);

	return 0;
}
