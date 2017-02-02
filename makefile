all: puzzling.dat

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

clean:
	-rm -rf puzzling.php puzzling.dat intermediate1.php intermediate2.php
