CC=cc
CFLAGS = -g -Wall -Wextra -I. -lm

all: puzzling.dat

# De-code the payload, which ends up in puzzling.dat
puzzling.php: 95.211.231.143Uh3LiAoAAAMAAAEbNe0AAAAHfile
	echo "<?php" > puzzling.php
	sed -n -e '$$p' 95.211.231.143Uh3LiAoAAAMAAAEbNe0AAAAHfile >> puzzling.php

fpuzzling.php: puzzling.php
	/home/bediger/src/php/revphp/pp.php puzzling.php > fpuzzling.php

intermediate1.php: puzzling.php
	cat puzzling.php | sed 's/eval(/print(/g' > intermediate1.php

intermediate2.php: intermediate1.php
	echo "<?php" > intermediate2.php
	php intermediate1.php | sed 's/if(!@isset(._SERVER)).*eval(.d);//' >> intermediate2.php
	echo 'print($$d);' >> intermediate2.php

puzzling.dat: intermediate2.php
	php intermediate2.php > puzzling.dat

# Build xor-decoding utilities
keysize: keysize.c
	$(CC) $(CFLAGS) -o keysize keysize.c

findkeys: findkeys.c php_vector.h base64_vector.h xencode_vector.h chars_array.h chars_array.o
	$(CC) $(CFLAGS) -o findkeys findkeys.c chars_array.o

chars_array.o:chars_array.c chars_array.h
	$(CC) $(CFLAGS) -c chars_array.c

xor: xor.c
	$(CC) $(CFLAGS) -o xor xor.c

clean:
	-rm -rf puzzling.php puzzling.dat intermediate1.php intermediate2.php keysize
	-rm -rf xor findkeys chars_array.o
