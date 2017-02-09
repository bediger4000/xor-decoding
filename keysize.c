#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

int hamming_dist(unsigned char *string1, unsigned char *string2, int sting_length_bytes);

#define MIN_KEY_LENGTH 2
#define MAX_KEY_LENGTH 30

int
main(int ac, char **av)
{
	char *filename = av[1];
	struct stat sb;
	unsigned char *ciphertext_buffer;
	size_t cc, ciphertext_size;
	FILE *fin;

	if (ac < 2)
	{
		fprintf(stderr, "keysize: estimate key length(s) using Hamming Distance\n");
		fprintf(stderr, "Usage: keysize <filename>\n");
		exit(1);
	}

	if (-1 == stat(filename, &sb))
	{
		fprintf(stderr, "Could not stat \"%s\": %s\n",
			filename, strerror(errno));
		exit(2);
	}

	ciphertext_size = sb.st_size;

	if (NULL == (fin = fopen(filename, "r")))
	{
		fprintf(stderr, "Could not fopen(%s) for read: %s\n",
			filename, strerror(errno));
		exit(3);
	}

	ciphertext_buffer = malloc(ciphertext_size);

	if (ciphertext_size != (cc = fread(ciphertext_buffer, 1, ciphertext_size, fin)))
	{
		fprintf(stderr, "Wanted to read %lu bytes of ciphertext, read only %lu bytes\n",
			cc, ciphertext_size
		);

		exit(4);
	}

	fprintf(stderr, "Read all %lu bytes of cipher text from \"%s\"\n",
		ciphertext_size, filename);

	fclose(fin);

	/* At this point, cipertext_buffer points to an in-memory copy of the
	 * xor encoded contents of the file. Try key lengths from MIN_KEY_LENGTH
	 * to MAX_KEY_LENGTH, calculate "normalized Hamming distance" for each key
	 * length. */

	for (int keysize = MIN_KEY_LENGTH; keysize < MAX_KEY_LENGTH; ++keysize)
	{
		double sum_hamming_distances = 0.0;
		int number_comparisons = 0;

		int limit = ciphertext_size - keysize;

		/* This loop walks the buffer in keysize chunks. For each chunk after the
		 * first keysize bytes, calculate the Hamming Distance from the first
		 * keysize bytes in file to the next keysize bytes.  */
		for (int i = keysize; i < limit; i += keysize, ++number_comparisons)
			sum_hamming_distances += hamming_dist(ciphertext_buffer, &ciphertext_buffer[i], keysize);

		printf("%d\t%.0f\t%.4f\n", keysize, sum_hamming_distances, sum_hamming_distances/(double)(keysize*number_comparisons));
	}

	return 0;
}

/* Bit-wise Hamming Distance from string s1 to string s2, both of which
 * have length in bytes of len, and not necessarily null-terminated.
 *
 * len and key length typically numerically equal.
 */
char bitmask[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};
int
hamming_dist(unsigned char *s1, unsigned char *s2, int len)
{
	int dist = 0;

	for (int i = 0; i < len; ++i)
	{
		char val = s1[i] ^ s2[i];

		while (val)
		{
			++dist;
			val &= val - 1;
		}
	}

	return dist;
}
