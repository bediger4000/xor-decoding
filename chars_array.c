#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <chars_array.h>

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

int
increment(struct chars_array *ary, int arylength)
{
	int carry = 0;
	int idx = arylength - 1;

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

void free_chars_array(struct chars_array *ary, int length)
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
