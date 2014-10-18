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


/* Generate the next combination of k_idxs, selecting t indicies
	 from the set [0,n).

	 This algorithm is fairly trivial and should be self-explanatory.

	 returns 0 on success, 1 on final combination, -1 on failure.
 */
int next_combination(unsigned *k_idxs, unsigned n, unsigned t){
	if (t > n || t < 1)
		return fail(EINVAL);

	if (k_idxs[t-1] + 1 < n){
		k_idxs[t-1]++;
		return 0;
	} else if (t == 1)
		return 1;
	else {
		for (int i = t - 2; i >= 0; i--){
			if (k_idxs[i] + 1 < k_idxs[i+1]){
				k_idxs[i++]++;
				for (;i < t; i++)
					k_idxs[i] = k_idxs[i-1] + 1;
				return 0;
			}
		}
		return 1;
	}
}

/* returns 1 on failure, 0 on success, -1 on error */

#define CHECK_FAIL(pred, err, label) if (pred) { saved_errno = (err); goto label; }

int check_recovery(size_t size, unsigned n, unsigned t){
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

	shamir_poly_t *p = malloc(poly_size);
	CHECK_FAIL(!p, ENOMEM, err1);

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
		if (ret){
			/* Secret recovery failed */
			failure = 1;
			for (unsigned i = 0; i < t; i++)
				debug("(%d,%d)", *(_k + (i * params.t)), *(_k + (i * params.t) + 1));
			break;
		}

		ret = next_combination(k_idxs, n, t);
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

int main (int argc, char **argv){
	int ret;
	char str[16];

	for (unsigned n = 2; n < 10; n++){
		for (unsigned t = 2; t < n; t++){
			ret = check_recovery(4096, n, t);
			if (ret == -1){
				snprintf(str, sizeof(str), "n: %d t: %d", n, t);
				perror(str);
				abort();
			} else if (ret == 1){
				abort();
			}
		}
	}
	return 0;
}
