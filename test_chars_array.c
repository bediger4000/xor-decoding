#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <chars_array.h>
int
main(int ac, char **av)
{
	int keylength = 3;
	char **keystrings;
	char *keystring = calloc(keylength + 1, 1);

	keystrings = malloc(sizeof(keystrings[0])*4);
	keystrings[0] = strdup("abc");
	keystrings[1] = strdup("1234");
	keystrings[2] = strdup("WX");
	keystrings[3] = NULL;
	/* 3 * 4 * 2 = 24, should output 24 distinct strings */

	struct chars_array *keychars = convert_keybytes(keystrings, keylength);

	while (1)
	{
		for (int i = 0; i < keylength; ++i)
			keystring[i] = keychars[i].bytes[keychars[i].current_byte];

		printf("\"%s\"\n", keystring);

		if (increment(keychars, keylength)) break;
	}

	free_chars_array(keychars, keylength);
	keychars = NULL;

	free(keystring);
	keystring = NULL;

	free(keystrings);
	keystrings = NULL;

	return 0;
}
