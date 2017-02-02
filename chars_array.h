struct chars_array {
	char *bytes;
	int bytes_count;
	int current_byte;
};

struct chars_array *convert_keybytes(char **array_of_arrays, int arylength);

int increment(struct chars_array *ary, int arylength);
void free_chars_array(struct chars_array *ary, int length);
