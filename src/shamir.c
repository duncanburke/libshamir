#include "config.h"

#include "shamir.h"
#include "g256_tables.h"

#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>


#define GF256_MASK ((1 << 8) - 1)
#define MAX_KEYS 255

static int fail(int _errno){
	errno = _errno;
	return -1;
}

int params_invalid(shamir_params_t params){
	return (params.threshold < 2 ||
					params.threshold > MAX_KEYS ||
					params.size < 1);
}

ssize_t shamir_poly_size(shamir_params_t params){
	if (params_invalid(params))
		return fail(EINVAL);
	return params.size * params.threshold;
}

ssize_t shamir_key_size(shamir_params_t params){
	if (params_invalid(params))
		return fail(EINVAL);
	return params.size + 1;
}

#include <stdio.h>
#define debug(M, ...) fprintf(stderr, "DEBUG %s:%d: " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)

/* The variables i and j have special meanings.
	 i indexes the coefficients of the polynomials and the keys.
	 j indexes the byte offset within the secret and keys.

	 The following invariants hold:
	 0 <= i < params.threshold <= MAX_KEYS
	 0 <= j < params.size

	 Note that params.threshold is the number of coefficients in each polynomial.
*/

/*
	The i-th coefficient for the j-th polynomial.
*/
#define _c(params, p, i, j) (*(p + (j * params.threshold) + i))

/*
	The i-th key
*/
#define _k(params, k, i) (k + (i * (params.size+1)))

/*
	The x value of the i-th key
*/
#define _k_x(params, k, i) (*_k(params,k,i))

/*
	The j-th y value of the i-th key
*/
#define _k_y(params, k, i, j) (*(_k(params,k,i) + j + 1))

#ifdef HAVE_RANDOM_DEVICE
int __shamir_rand_fd=-1;

int __attribute__((weak)) _shamir_init_random(){
	if (__shamir_rand_fd != -1)
		return fail(EINVAL);
	__shamir_rand_fd = open(RANDOM_DEVICE, O_RDONLY);
	if (__shamir_rand_fd == -1)	return -1;
	return 0;
}

int __attribute__((weak)) _shamir_get_random(void *buf, size_t buflen){
	if ((__shamir_rand_fd == -1)|| !buf || !buflen)
		return fail(EINVAL);
	size_t to_read = buflen;
	uint8_t *ptr = buf;
	ssize_t ret;
	while (to_read) {
		ret = read(__shamir_rand_fd, ptr, to_read);
		if (ret == -1) return -1;
		ptr += ret;
		to_read -= ret;
	}
	return 0;
}

int __attribute__((weak)) _shamir_cleanup_random(){
	if (__shamir_rand_fd == -1)
		return fail(EINVAL);
	int ret = close(__shamir_rand_fd);
	if (ret == -1) return -1;
	__shamir_rand_fd = -1;
	return 0;
}
#else
#error "No random source"
#endif

int shamir_init_poly(shamir_params_t params, shamir_poly_t *p, uint8_t *secret){
	int saved_errno;
	int ret;

	if (!p || !secret || params_invalid(params))
		return fail(EINVAL);

	ret = _shamir_init_random();
	if (ret == -1) return -1;

	/* The polynomial is generated as follows:
		 All coefficients except the constant terms are generated randomly.
		 The constant terms are the bytes of the secret.
		 The highest-order coefficients are drawn from [0x01,0xff].
		 Other coefficients are drawn from [0x00,0xff].
	*/

	/* Start by setting the entire polynomial to random values */
	ret = _shamir_get_random(p, params.size*params.threshold);
	if (ret == -1) goto err_1;

	/* Redraw high-order coefficients until they are nonzero.
		 This is inefficient in terms of syscalls, but it's fairly improbable.
	*/

	for (unsigned j = 0; j < params.size; j++){
		while (!_c(params,p,params.threshold-1,j)){
			ret = _shamir_get_random(&_c(params,p,params.threshold-1,j), 1);
			if (ret == -1) goto err_1;
		}
	}

	/* Set the constant coefficients to the bytes of the secret
	*/
	for (unsigned j = 0; j < params.size; j++)
		_c(params, p, 0, j) = secret[j];

	ret = _shamir_cleanup_random();
	if (ret == -1) return -1;

	return 0;

 err_1:
	saved_errno = errno;
	_shamir_cleanup_random();
	return fail(saved_errno);

}

/* Calculate the key k for the given x value.
	 The following will hold:

	 k[0] = x
	 k[i+1] = p_i(x)

	 where p_i is the i-th polynomial.

	 That is, the key is the x value followed by an array of the values of the polynomials
	 evaluated at x.
 */
int _shamir_get_key(shamir_params_t params, shamir_poly_t *p, gf256_t x, shamir_key_t *k){
	if (!p || !k || params_invalid(params) || (x < 1))
		return fail(EINVAL);

	unsigned log_x = log[x];
	_k_x(params,k,0) = x;

	for (unsigned j = 0; j < params.size; j++){
		int i = params.threshold - 1;
		unsigned y = _c(params, p, i--, j);
		for (;i >= 0; i--){
			if (y)
				y = exp[(log_x + log[y])%0xff];
			y ^= _c(params, p, i, j);
			y &= GF256_MASK;
		}
		_k_y(params,k,0,j) = (gf256_t)y;
	}
	return 0;
}

int shamir_get_keys(shamir_params_t params, shamir_poly_t *p, shamir_key_t *k, unsigned n){
	if (!p || !k || params_invalid(params) || n < 2 || n > MAX_KEYS)
		return fail(EINVAL);

	for (unsigned i = 0; i < n; i++){
		/* The x value for each key should be nonzero, in gf256, and unique among keys.
			 Use x = i+1 as this satisfies the required properties.
		*/
		int ret = _shamir_get_key(params, p, i+1, _k(params,k,i));
		if (ret == -1) return -1;
	}
	return 0;
}

int shamir_recover_secret(shamir_params_t params, shamir_key_t *k, uint8_t *secret){
	if (!k || !secret || params_invalid(params))
		return fail(EINVAL);

	for (unsigned j = 0; j < params.size; j++){
		secret[j] = 0;
		for (unsigned i = 0; i < params.threshold; i++){
			/* The discrete log of the numerator and denominator of the lagrange terms */
			unsigned log_n = 0, log_d = 0;

			for (unsigned _i = 0; _i < params.threshold; _i++){
				if (i == _i) continue;
				log_n += log[_k_x(params, k, _i)];
				log_d += log[_k_x(params, k, i) ^ _k_x(params, k, _i)];
			}
			/* Take log_n - log_d mod 255 to do division in the multiplicative group
				 for the fraction part of the lagrange term.
				 log_l is volatile so that the term will always be evaluated regardless
				 of whether y = 0.
			*/
			volatile unsigned log_l = (((log_n%0xff) + 0xff) - (log_d%0xff))%0xff;
			unsigned y = _k_y(params,k,i,j);
			if (y)
				secret[j] ^= exp[(log[y] + log_l)%0xff];
		}
	}
	return 0;
}

/* Generate the next combination of idxs, selecting b indicies
	 from the set [0,a).

	 returns 0 on success, 1 on final combination, -1 on failure.
 */

int _shamir_next_combination(unsigned *idxs, unsigned a, unsigned b){
	if (b > a || b < 1)
		return fail(EINVAL);

	if (idxs[b-1] + 1 < a){
		idxs[b-1]++;
		return 0;
	} else if (b == 1)
		return 1;
	else {
		for (int i = b - 2; i >= 0; i--){
			if (idxs[i] + 1 < idxs[i+1]){
				idxs[i++]++;
				for (;(unsigned)i < b; i++)
					idxs[i] = idxs[i-1] + 1;
				return 0;
			}
		}
		return 1;
	}
}


static int _shamir_recover_poly_partial(shamir_params_t params, shamir_key_t *k, unsigned lagrange_term, unsigned term_degree){
	if (term_degree == params.threshold - 1)
		return 1;

	unsigned n_constants = (params.threshold-1) - term_degree;
	unsigned idxs[n_constants];
	unsigned partial_term = 0;
	int ret = 0;

	for (unsigned i = 0; i < n_constants; i++){
		idxs[i] = i;
	}

	for (;;) {
		unsigned log_partial_subterm = 0;
		for (unsigned i = 0; i < n_constants; i++){
			unsigned idx = idxs[i];
			if (idx >= lagrange_term) idx++;
			log_partial_subterm += log[_k_x(params, k, idx)];
		}
		partial_term ^= exp[log_partial_subterm % 0xff];

		if (term_degree)
			ret = _shamir_next_combination(idxs, params.threshold-1, n_constants);

		if (ret == -1)
			return -1;
		else if (ret || (term_degree == 0))
			return partial_term;
	}
}

int shamir_recover_poly(shamir_params_t params, shamir_key_t *k, shamir_poly_t *p){
	if (!k || !p || params_invalid(params))
		return fail(EINVAL);

	memset(p, 0, params.size * params.threshold);

	for (unsigned i = 0; i < params.threshold; i++){
		/* loop over the terms of the lagrange polynomial */
		unsigned log_d = 0;

		for (unsigned _i = 0; _i < params.threshold; _i++){
			/* calculate the denominator of the lagrange term */
			if (i == _i) continue;
			log_d += log[_k_x(params, k, i) ^ _k_x(params, k, _i)];
		}
		unsigned log_lagrange_factor = (0xff - (log_d%0xff))%0xff;

		for (unsigned _i = 0; _i < params.threshold; _i++){
			/* calculate the partial contribution of the lagrange term to each
				 degree term _i of the polynomial */

			int partial_term = _shamir_recover_poly_partial(params,k,i,_i);
			if (partial_term == -1)	return -1;
			if (partial_term){
				for (unsigned j = 0; j < params.size; j++){
					/* loop over the independent polynomials */
					gf256_t y = _k_y(params,k,i,j);

					if (y)
						_c(params,p,_i,j) ^= exp[((unsigned)log[partial_term] + log_lagrange_factor + (unsigned)log[y]) % 0xff];
				}
			}
		}
	}

	return 0;
}
