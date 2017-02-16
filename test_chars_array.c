#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <chars_array.h>
int
main(int ac, char **av)
{
	int keylength = ac - 1;
	char **keystrings;
	char *keystring = calloc(keylength + 1, 1);

	keystrings = malloc(sizeof(keystrings[0])*(keylength + 1));

	for (int k = 1; k < ac; ++k)
	{
		keystrings[k-1] = strdup(av[k]);
	}

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
