#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <math.h>
#include <ctype.h>

#include <php_vector.h>
#include <base64_vector.h>
#include <xencode_vector.h>
#include <chars_array.h>

void find_keys(unsigned char *ciphertext_buffer, size_t ciphertext_size, int min_key_length, int max_key_length);
double find_key(unsigned char *ciphertext_buffer, size_t ciphertext_size, int keylength);
char *find_likely_keys(char *ciphertext_buffer, int ciphertext_size);
double vector_angle(int vector[256]);
unsigned char *fill_buffer(char *filename, size_t *size_out);
double iterate_keystrings(
	unsigned char *ciphertext_buffer,
	size_t ciphertext_size,
	char **keystrings,
	int keylength,
	char *keystring_out
);
char *escape_chars(char *string, char *buffer);
void usage(char *progname);

double *basis_vector;
double basis_vector_magnitude;
int allowable_non_printable_percent = 0;

int
main(int ac, char **av)
{
	char *filename = NULL;
	int c;

	unsigned char *ciphertext_buffer;
	size_t ciphertext_size;

	int min_key_length = 2;
	int max_key_length = 30;

	basis_vector = php_vector;
	basis_vector_magnitude = php_vector_magnitude;

	while (EOF != (c = getopt(ac, av, "bi:j:N:n:px")))
	{
		switch (c)
		{
		case 'b':
			basis_vector = base64_vector;
			basis_vector_magnitude = base64_vector_magnitude;
			break;
		case 'i':
			filename =  optarg;
			break;
		case 'j':
			allowable_non_printable_percent = strtol(optarg, NULL, 10);
			break;
		case 'N':
			max_key_length = strtol(optarg, NULL, 10);
			break;
		case 'n':
			min_key_length = strtol(optarg, NULL, 10);
			break;
		case 'p':
			basis_vector = php_vector;
			basis_vector_magnitude = php_vector_magnitude;
			break;
		case 'x':
			basis_vector = xencode_vector;
			basis_vector_magnitude = xencode_vector_magnitude;
			break;
		}
	}

	if (!filename)
		filename = av[optind];

	if (!filename) usage(av[0]);

	ciphertext_buffer = fill_buffer(filename, &ciphertext_size);

	find_keys(ciphertext_buffer, ciphertext_size, min_key_length, max_key_length);

	free(ciphertext_buffer);
	ciphertext_buffer = NULL;

	return 0;
}

void
find_keys(unsigned char *ciphertext_buffer, size_t ciphertext_size, int min_key_length, int max_key_length)
{
	double min_angle = 10.00;
	int best_keylength = -1;

	for (int keylength = min_key_length; keylength < max_key_length; ++keylength)
	{
		double angle = find_key(ciphertext_buffer, ciphertext_size, keylength);
		if (angle < min_angle)
		{
			min_angle = angle;
			best_keylength = keylength;
		}
	}

	printf("Best key length: %d\n", best_keylength);
}

double
find_key(unsigned char *ciphertext_buffer, size_t ciphertext_size, int keylength)
{
	char **byte_buckets = malloc(sizeof(char *)*keylength);
	int bytes_per_bucket = ciphertext_size/keylength + 1; // Integer division rounding.
	int *bucket_count = calloc(sizeof(int), keylength);
	double best_angle = 7.00;

	for (int i = 0; i < keylength; ++i)
		byte_buckets[i] = calloc(bytes_per_bucket, 1);

	// Break ciphertext into keylength number of "buckets" of bytes.
	for (unsigned int i = 0; i < ciphertext_size; ++i)
	{
		int bucket_number = i%keylength;
		byte_buckets[bucket_number][bucket_count[bucket_number]++] = ciphertext_buffer[i];
	}

	// Now we have keylength number of arrays of bytes: byte_buckets[]
	// Each byte_bucket[n] has bucket_count[n] bytes in it.
	char **keystrings = calloc(sizeof(char *)*keylength, 1);

	for (int i = 0; i < keylength; ++i)
		keystrings[i] = find_likely_keys(byte_buckets[i], bucket_count[i]);

	char *first_best_keystring = calloc(keylength + 1, 1);
	for (int i = 0; i < keylength; ++i)
		first_best_keystring[i] = keystrings[i][0];
	first_best_keystring[keylength] = '\0';

	char escaped_string[1024];

	if (first_best_keystring[0])
		printf("Key length %d, first best key string \"%s\"\n", keylength, escape_chars(first_best_keystring, escaped_string));

	if (strlen(keystrings[0]) > 0)
	{
		char *best_keystring = calloc(keylength + 1, 1);
		best_angle = iterate_keystrings(ciphertext_buffer, ciphertext_size, keystrings, keylength, best_keystring);

		printf("Key length %d, best key string \"%s\"\n",
			keylength,
			escape_chars(best_keystring, escaped_string)
		);
		fflush(stdout);

		free(best_keystring);
		best_keystring = NULL;
	} else {
		printf("Key length %d, no good key string\n", keylength);
	}

	free(first_best_keystring);
	first_best_keystring = NULL;

	for (int i = 0; i < keylength; ++i)
	{
		free(keystrings[i]);
		keystrings[i] = NULL;
	}

	free(keystrings);
	keystrings = NULL;

	free(bucket_count);
	bucket_count = NULL;
	for (int i = 0; i < keylength; ++i)
	{
		free(byte_buckets[i]);
		byte_buckets[i] = NULL;
	}
	free(byte_buckets);
	byte_buckets = NULL;
	
	return best_angle;
}

char *
find_likely_keys(char *ciphertext_buffer, int ciphertext_size)
{
	struct {
		unsigned char byte;
		double angle;
	} best_bytes[3];

	best_bytes[0].byte = '\0';
	best_bytes[1].byte = '\0';
	best_bytes[2].byte = '\0';

	best_bytes[0].angle = 10.0;
	best_bytes[1].angle = 11.0;
	best_bytes[2].angle = 12.0;

	int vector[256];
	int non_printable_limit = ciphertext_size*allowable_non_printable_percent/100 + 1;

	// This leaves out tabs, newlines, carriage returns as key byte values.
	for (unsigned int keybyte = 0x20; keybyte < 0x7f; ++keybyte)
	{
		if (!isalnum(keybyte)) continue;

		for (int i = 0; i < 256; ++i) vector[i] = 0;
		int not_printable_count = 0;

		for (int i = 0; i < ciphertext_size; ++i)
		{
			unsigned char plaintext_byte = keybyte ^ ciphertext_buffer[i];
			if (!isprint(plaintext_byte) && !isspace(plaintext_byte)) ++not_printable_count;
			++vector[(int)plaintext_byte];
		}

		if (not_printable_count > non_printable_limit) continue;

		double angle = vector_angle(vector);
		// Singe all components of both vectors are positive, all we
		// really want to look for is the smallest angle(s).

		double tmp_angle;
		char tmp_byte;
		unsigned char savebyte = keybyte;
		if (angle < best_bytes[0].angle)
		{
			tmp_angle = best_bytes[0].angle;
			best_bytes[0].angle = angle;
			angle = tmp_angle;
			tmp_byte = best_bytes[0].byte;
			best_bytes[0].byte = savebyte;
			savebyte = tmp_byte;
		}
		if (angle > best_bytes[0].angle && angle < best_bytes[1].angle)
		{
			tmp_angle = best_bytes[1].angle;
			best_bytes[1].angle = angle;
			angle = tmp_angle;
			tmp_byte = best_bytes[1].byte;
			best_bytes[1].byte = savebyte;
			savebyte = tmp_byte;
		}
		if (angle > best_bytes[1].angle && angle < best_bytes[2].angle)
		{
			best_bytes[2].angle = angle;
			best_bytes[2].byte = savebyte;
		}
	}

	char *keybytes = calloc(4, 1);
	int byteidx = 0;
	for (int i = 0; i < 3; ++i)
	{
		if (best_bytes[i].byte)
			keybytes[byteidx++] = best_bytes[i].byte;
		else break;
	}

	return keybytes;
}

double
vector_angle(int vector[256])
{
	double angle = 0.0;
	double dot_product = 0.0;
	double sum_of_squares = 0.0;

	for (int i = 0; i < 256; ++i)
	{
		dot_product += basis_vector[i] * (double)vector[i];
		sum_of_squares += (double)vector[i]*(double)vector[i];
	}

	angle = acos(dot_product/(basis_vector_magnitude * sqrt(sum_of_squares)));

	return angle;
}

unsigned char *
fill_buffer(char *filename, size_t *size_out)
{
	struct stat sb;
	unsigned char *ciphertext_buffer;
	size_t cc, ciphertext_size;
	FILE *fin;

	if (-1 == stat(filename, &sb))
	{
		fprintf(stderr, "Could not stat \"%s\": %s\n",
			filename, strerror(errno));
		exit(1);
	}

	ciphertext_size = sb.st_size;

	if (NULL == (fin = fopen(filename, "r")))
	{
		fprintf(stderr, "Could not fopen(%s) for read: %s\n",
			filename, strerror(errno));
		exit(2);
	}

	ciphertext_buffer = malloc(ciphertext_size);

	if (ciphertext_size != (cc = fread(ciphertext_buffer, 1, ciphertext_size, fin)))
	{
		fprintf(stderr, "Wanted to read %lu bytes of ciphertext, read only %lu bytes\n",
			cc, ciphertext_size
		);

		exit(3);
	}

	fclose(fin);

	fprintf(stderr, "Read all %lu bytes of cipher text from \"%s\"\n",
		ciphertext_size, filename);

	*size_out = ciphertext_size;

	return ciphertext_buffer;
}

double
iterate_keystrings(
	unsigned char *ciphertext_buffer,
	size_t ciphertext_size,
	char **keystrings,
	int keylength,
	char *keystring_out
)
{
	double best_angle = 10.0;
	char *keystring = calloc(keylength + 1, 1);
	struct chars_array *keychars = convert_keybytes(keystrings, keylength);

	while (1)
	{
		int vector[256];
		for (int i = 0; i < 256; ++i) vector[i] = 0;

		for (int i = 0; i < keylength; ++i)
			keystring[i] = keychars[i].bytes[keychars[i].current_byte];

		for (unsigned int i = 0; i < ciphertext_size; ++i)
			++vector[keystring[i%keylength]^ciphertext_buffer[i]];

		double angle = vector_angle(vector);

		if (angle < best_angle)
		{
			best_angle = angle;
			strcpy(keystring_out, keystring);
		}

		if (increment(keychars, keylength)) break;
	}

	free_chars_array(keychars, keylength);
	keychars = NULL;

	free(keystring);
	keystring = NULL;

	return best_angle;
}

char *
escape_chars(char *string, char *buffer)
{
	char *p = string;
	char *d = buffer;

	while (*p != '\0')
	{
		if (isprint(*p))
		{
			if (*p == '\t') {
				*d++ = '\\';
				*d++ = 't';
			} else if (*p == '\r') {
				*d++ = '\\';
				*d++ = 'r';
			} else if (*p == '\n') {
				*d++ = '\\';
				*d++ = 'n';
			} else
				*d++ = *p;
		} else {
			*d++ = '\\';
			*d++ = 'x';
			sprintf(d, "%02x", *p);
			d += 2;
		}
		++p;
	}

	*d = '\0';

	return buffer;
}

void
usage(char *progname)
{
	fprintf(stderr, "%s: make best guess at key of xor-encoded ciphertext\n", progname);
	fprintf(stderr, "usage: %s [-b|-p|-x] -i inputfilename [-j <number>] -N <maxkeylength> -n <minkeylenght>\n", progname);
	fprintf(stderr, "Flags:\n"
					"-b  base64 encoding basis vector\n"
					"-p  PHP source code basis vector (default)\n"
					"-x  PHP '\\xnm' string rep basis vector\n"
					"-i <inputfilename> specify the file name of xor-encoded ciphertext, no default\n"
					"-j <number> allow <number> percent of non-printing characters when guessing key, default zero\n"
					"-n <number> specify minimum key length to consider, default 2\n"
					"-N <number> specify maximum key length to consider, default 30\n"
	);
	exit(0);
}
