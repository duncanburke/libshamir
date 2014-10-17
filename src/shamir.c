#include "config.h"

#include "shamir.h"
#include "g256_tables.h"

#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>


#define GF256_MASK ((1 << 8) - 1)
#define MAX_KEYS 254

#define SHAMIR_URANDOM

int fail(int _errno){
	errno = _errno;
	return -1;
}

int params_invalid(shamir_params_t params){
	return (params.threshold < 2 ||
					params.threshold > MAX_KEYS ||
					params.size < 1);
}

ssize_t shamir_poly_size(shamir_params_t params){
	if (params_invalid)
		return fail(EINVAL);
	return (params.size * params.threshold) * sizeof(gf256_t);
}

ssize_t shamir_key_size(shamir_params_t params){
	if (params_invalid)
		return fail(EINVAL);
	return (params.size + 1) * sizeof(gf256_t);
}



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
#define _k(params, k, i) (k + (i * params.threshold))

/*
	The x value of the i-th key
*/
#define _k_x(params, k, i) (*_k(params,k,i))

/*
	The j-th y value of the i-th key
*/
#define _k_y(params, k, i, j) (*(_k(params,k,i) + j + 1))



int shamir_init_poly(shamir_params_t params, shamir_poly_t *p, uint8_t *secret){
	if (!p || !secret || params_invalid(params))
		return fail(EINVAL);

	ssize_t poly_size = shamir_poly_size(params);
	if (poly_size == -1) return -1;

#ifdef HAVE_RANDOM_DEVICE
	int fd = open(RANDOM_DEVICE, O_RDONLY);
	if (fd == -1)
		return -1;

	size_t to_read = poly_size;
	uint8_t *_p = p;
	ssize_t ret;

	while (to_read) {
		ret = read(fd, _p, to_read);
		if (ret == -1){
			int saved_errno = errno;
			close(fd);
			return fail(saved_errno);
		}
		_p += ret;
		to_read -= ret;
	}
#else
#error "No random source"
#endif

	/* Set the constant terms of the polynomials
		 to the bytes of the secret
	*/
	for (unsigned j = 0; j < params.size; j++)
		_c(params, p, 0, j) = secret[j];
	return 0;
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
				y = exp[log_x + log[y]];
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
			unsigned log_n, log_d = 0;

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
			volatile unsigned log_l = ((log_n%0xff) + 0xff) - (log_d%0xff);
			unsigned y = _k_y(params,k,i,j);
			if (y)
				secret[j] ^= exp[log[y] + log_l];
		}
	}
}
