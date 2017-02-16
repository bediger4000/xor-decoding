#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <chars_array.h>

/* Takes an array of pointers to arrays, each of those sub-arrays a nul-terminated string,
 * and the number of subarrays. Converts to a struct chars_array, which allows iterating
 * through all the strings that the sub-arrays can create together. Assumes that the
 * a sub-array at position N has characters that should appear in the strings at
 * index N.
 */
struct chars_array *
convert_keybytes(char **array_of_arrays, int arylength)
{
	struct chars_array *r = calloc(sizeof(struct chars_array)*arylength, 1);

	for (int i = 0; i < arylength; ++i)
	{
		r[i].bytes = array_of_arrays[i];
		r[i].bytes_count = strlen(r[i].bytes);  // Which implies the arrays are ASCII-Nul terminated.
		r[i].current_byte = 0;

		array_of_arrays[i] = NULL;
	}

	return r;
}

/* Increment to the next string. Careful: this struct handles a variable number of
 * variable length arrays of chars, one array of chars for each index in the strings
 * it iterates through.
 * Return value is zero, as long as there's still unique strings left to iterate
 * through. When all strings have been iterated, it returns 1 - it has "carried"
 * to the next "digit", which doesn't exist.
 */
int
increment(struct chars_array *ary, int arylength)
{
	int carry = 0;
	int idx = arylength - 1; /* Least significant character */

	do {
		++ary[idx].current_byte;
		if (ary[idx].current_byte >= ary[idx].bytes_count)
		{
			ary[idx].current_byte = 0;
			--idx;
			carry = 1;
		} else {
			carry = 0;
			break;
		}
	} while (idx >= 0);

	return carry;
}

void
free_chars_array(struct chars_array *ary, int length)
{
	for (int i = 0; i < length; ++i)
	{
		if (ary[i].bytes)
		{
			free(ary[i].bytes);
			ary[i].bytes = NULL;
		}
	}
	free(ary);
}
