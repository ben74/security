<?php
/*
usage :
$isblocked=Alpow\Security\Security::blockMaliciousRequests();
 */

namespace Alpow\Security;

class Security
{

    static function blockMaliciousRequests($url = null, $rawBody = null, $req = null, $lp = 'logs', $files = null)
    {
        if (!$url) {
            $url = $_SERVER['REQUEST_URI'];
        }
        if (!$rawBody) {
            $rawBody = file_get_contents('php://input');
        }
        if (!$req and $_REQUEST) {
            $req = $_REQUEST;
        }
        if (!$files and $_FILES) {
            $files = $_FILES;
        }
        if ($url) {
            $x = static::injectionPattern($url);#check the uri along with query string .. avoiding injection via rewriting within where like requests ..
            if ($x) {
                return 'injection pattern ' . $x . ' in url ' . $url;#and querystring
            }
        }

        if ($rawBody) {
            $x = static::injectionPattern($rawBody);#check the uri alondg with query string
            if ($x) {
                return 'injection pattern ' . $x . ' in rawBody';
            }
        }

        if ($req && 'query string parameters goes here ..') {
            foreach ($req as $k => $v) {
                if (in_array($k, ['contacts_societe', 'contacts_message'])) {
                    continue;
                }#skip those
                $x = static::injectionPattern($v);
                if ($x) {
                    return 'injection pattern k:' . $x . ' in ' . $v;
                }
                $x = static::injectionPattern($k);
                if ($x) {
                    return 'injection pattern v:' . $x . ' in ' . $k;
                }
            }
        }

        if (isset($files) and $files) {
            $json = json_encode($files);
            if (preg_match('~"name":"[^\"]+\.php[^\"]*"~i', $json, $m)) {#way much more simpler but wont work for more complex ..
                return 'file upload: ' . $m[0];
            }
            if (preg_match('~":"[^\"]+\.php[^\"]*"~i', $json, $m)) {
                return 'complex nested file upload: ' . $m[0];
            }
            $foundUploads = searchInArrayDepths($files, ['name'], '~\.php~');
            if ($foundUploads) {
                return 'deep file upload: ' . json_encode($foundUploads);
            }
        }
        return false;#clear :)
    }

    static function injectionPattern($x)
    {
        /* recursive returns first positive match */
        if (is_array($x)) {
            foreach ($x as $v) {
                $res = static::injectionPattern($v);
                if ($res && 'returns first found') {
                    return $res;
                }
            }
            return false;
        }

        /* most common possible injection patterns '--', '||',  'grant ','create ',  */
        $sqlInjectionPatterns = ['/*', '*/', 'sleep(', 'GET_HOST_NAME', 'drop ', 'truncate ', ' delete ', 'cast(', 'ascii(', 'char(', '@@', '<script', '<ifram', '<img'];
        foreach ($sqlInjectionPatterns as $v) {
            if (stripos($x, $v) !== false) {
                return $v;
            }
        }

        if (Preg_Match("~' *or|\" *or|or *1 *= *1|union *all~i", $x, $m) && !Preg_Match("~[l|d]' *or~i", $x, $m) && 'pas anodin ..') {
            return $m[0];
        }

        if (Preg_Match("~url\(|data:image|/png;|base64,|option=com_xmap&view=xml&tmpl=component~i", $x, $m)) {
            return $m[0];
        }
        if (Preg_Match("~_users|\~root|print-439573653|/RK=|/RS=|concat\(|0x3a,password,usertype\)|http://http://|\*!union\*|plugin=imgmanager|w00tw00t|zologize/axa|HNAP1/|admin/file_manager|%63%67%69%2D%62%69%6E|%70%68%70?%2D%64+|cash+loans+|webdav/|cgi-bin|php?-d|union%20all%20select|convert%28int%2C~i", $x, $m)) {
            return $m[0];
        }
        return;#nothing found
    }

    static function _die($x = null)
    {
        $_ENV['die'] = 1;
        static::gt('_die, breakpoint here is a good idea');#caught at shutdown function, is neat :)
        if ($x && in_array(gettype($x), ['array', 'object'])) {
            print_r($x);
        } elseif ($x) {
            echo $x;
        }
        #$e=error_get_last();
        die;#launch gc then shutdown functions at end
    }

    static function r404($x = '', $y = '')
    {
        header('HTTP/1.0 404 Not Found', 1, 404);
        static::_die('/* <a href="/">not found : ' . trim($x, ' */') . ' </a><script>location.href="/#' . str_replace('"', '', $x) . '";</script>*/');
    }

    static function dbm($x, $sub = null, $f = null)
    {#todo:if config send debug to url ....
        return;
        if (DEV or LOCAL) {
            return;
        }#$a=1;DEVBREAKPOINT
        $bt = static::bt(1);
        if (!$sub) {
            $sub = $_ENV['h'] . ' debug';
        }

        $json = ['host' => 'dssd', 'type' => 'debug', 'k' => $sub, 'k2' => $_ENV['h'] . $_ENV['u'], 'v' => $x];
        $a1 = date('ymd');
        $b1 = date('dmy');
        $headers = ["sd1"];
        $url = 'dr.php';
        $opt = [
            10015 => json_encode($json),#post payload
            10023 => ["Cookie: a1=$a1;b1=$b1"],#all headers as one array, sets
            10002 => $url,
            10036 => 'POST',
            19913 => 1,
            42 => 1,
            45 => false,
            81 => false,
            64 => false,
            13 => 10,
            78 => 10,#timeout
            52 => 1, #redir
            2 => 1,
            41 => 1,
            58 => 1,  #?? Follow Return Headers
        ];
        $_sent = cuo($opt);
        return;

        $opt = $headers = [];
        $from = 'dx24.fr>';
        $to = 'dx24.fr';
        $post = [
            'from' => $from,
            'to' => $to,
            'sub' => $sub,
            'body' => '<pre>' . $sub . ' -- ' . date('YmdHis') . ' ' . $_ENV['h'] . $_ENV['u'] . "  {\n" . print_r(
                    [
                        'x' => $x/*Rhtmlspecialchars($x)*/,
                        'bt' => $bt,
                        'host' =>
                            $_ENV['h'],
                        'post' => $_POST,
                        'files' => $_FILES,
                        'get' => $_GET,
                        'cook' => $_COOKIE,
                        'ip' => $_ENV['IP']
                    ],
                    10
                )
        ];
        $_sent = static::cup($url, $opt, $post, $headers, 1);
        return;
        /*
        foreach($_ENV['debugMails'] as $mail){
            wmail($mail, $sub, '<pre>' . $sub . ' -- ' . date('YmdHis') . ' ' . $_ENV['h'].$_ENV['u'] . "  {\n" . print_r(compact('x', 'bt') + ['host' => $_ENV['h'], 'post' => $_POST, 'get' => $_GET, 'cook' => $_COOKIE, 'ip' => $_ENV['IP']], 1));
        }*/
        static::db($x, $f);
    }

    static function db($x, $f = null)
    {
        if (!$f) {
            $f = ini_get('error_log');
        }
        if (strpos($f, $_ENV['lp']) === false) {#anom.log
            $f = $_ENV['lp'] . $f;
        }
        $bt = static::bt(1);
        static::FPC($f, "\n\n}" . date('YmdHis') . ' ' . $_ENV['h'] . '/' . $_ENV['u'] . "{" . print_r(compact('x', 'bt'), 1) . json_encode(array_filter(['post' => $_POST, 'get' => $_GET, 'cook' => $_COOKIE, 'ip' => $_ENV['IP']]), 1) . "\n\n", 8);
    }

    static function FPC($f, $d, $o = null)
    {
        $f = str_replace('c:/home/', '', $f);#loclahost
        static $rec;
        $rec++;
        if (DEV and $rec > 2) {
            $_bt = debug_backtrace();
            $err = 'recursivity';
        }
        $path = explode('/', $f);
        $end = array_pop($path);
        $folder = implode('/', $path);
        if ($folder and !is_dir($folder)) {#/logs/c:/home/
            $ok = mkdir($folder, 0777, 1);
            if (!$ok) {
                db('cant mkdir ' . $folder, 'anom.log');
            }
        }
        $rec--;
        return file_put_contents($f, $d, $o);
    }

    static function arrayContains($array, $contains = 0, $lv = 0, $bk = [])
    {
        $found = [];
        foreach ($array as $k => $v) {
            if (is_array($v)) {
                $found = array_merge($found, static::arrayContains($v, $contains, $lv + 1, array_merge($bk, [$k])));
            } elseif (preg_match($contains, $v)) {
                #_die(["found:$k"=>$v]);
                $found[] = [$k => $v];
            }
        }
        return $found;
    }

    static function searchInArrayDepths($array, $keys = 0, $contains = 0, $lv = 0, $bk = ['root'])
    {
        if (!$keys) {
            $keys = explode(',', 'name,tmp_name');
        }
        $c = count($keys);
        $matching = 0;
        #if($lv==1)_die(compact('bk','array'));
        foreach ($keys as $key) {
            if (isset($array[$key])) {
                if (is_array($array[$key]) and $contains) {
                    $c1 = count(static::arrayContains($array[$key], $contains, 0, $key));
                    #_die($key.$contains.$c1);found twice
                    #echo $c1;
                    $matching += $c1;
                } elseif ($contains) {
                    if (preg_match($contains, $array[$key])) {
                        $matching++;
                    }
                } else {
                    $matching++;
                }
            }
        }
        if ($matching >= $c) {
            #_die("ok:$matching $c");
            return $array;
        }
        $found = [];
        foreach ($array as $k => $v) {
            if (is_array($v)) {
                $e = static::searchInArrayDepths($v, $keys, $contains, $lv + 1, array_merge($bk, [$k]));#search deeper
                if ($e) {
                    $found = array_merge($found, $e);
                    #_die("found::".$found);
                }
            }
        }
        return $found;
    }

    static function curlFile($url, $file, $name = '', $headers = [])
    {
        #die(realpath($file));
        if (!$name) {
            $name = basename($file);
        }#enctype : multipoart
        #$files=['file' => '@' . realpath($file).';filename='.$name];#does not sends files
        $files = ['file' => curl_file_create($file, '.jpg', $name)];#gives : error: operation aborted by callback
        return static::cup(['url' => $url, 'post' => $files, 'headers' => ['content-type: multipart/form-data'], 'headers' => $headers]);
    }

    static function cup($url, $opt = [], $post = [], $headers = [], $timeout = 10, $unsecure = 1, $forcePort = 0)
    {
        if (is_array($url)) {
            extract($url);
        }
        $ch = \curl_init();
        $headers[] = 'Expect:';/*100 header*/
        if (isset($opt[CURLOPT_URL]) and $opt[CURLOPT_URL]) {
            $url = $opt[CURLOPT_URL];
        }
        $opts = [CURLOPT_URL => $url, CURLOPT_HEADER => 1, CURLINFO_HEADER_OUT => 1, CURLOPT_VERBOSE => 1, CURLOPT_RETURNTRANSFER => 1, CURLOPT_AUTOREFERER => 1, CURLOPT_FOLLOWLOCATION => 1, CURLOPT_TIMEOUT => $timeout, CURLOPT_CONNECTTIMEOUT => $timeout, CURLOPT_HTTPHEADER => $headers];
        if ($unsecure) {
            $opts += [CURLOPT_SSL_VERIFYHOST => false, CURLOPT_SSL_VERIFYPEER => false];
        }
        if ($forcePort) {
            $opts += [CURLOPT_PORT => strpos($url, 'ttps:/') ? 443 : 80];
        }

        foreach ($opt as $k => $v) {
            $opts[$k] = $v;
        }#par dessus les options par défaut
        #$opts[CURLOPT_HTTPHEADER][] = 'Expect:';#in case of 100 continue soft "error"
        if ($post) {
            $opts[CURLOPT_POST] = 1;
            $opts[CURLOPT_POSTFIELDS] = $post;#$url2Callback[$url]['post']
        }
        \curl_setopt_array($ch, $opts);
        $result = \curl_exec($ch);
        $info = \curl_getinfo($ch);
        $error = \curl_error($ch);
        \curl_close($ch);
        $header = substr($result, 0, $info['header_size']);
        $contents = substr($result, $info['header_size']);
        return compact('contents', 'header', 'info', 'error', 'opts');
    }

    static function cuo($opts)
    {
        $curl = curl_init();
        curl_setopt_array($curl, $opts);
        $result = \curl_exec($curl);
        $info = \curl_getinfo($curl);
        $error = \curl_error($curl);
        \curl_close($curl);
        $header = substr($result, 0, $info['header_size']);
        $contents = trim(substr($result, $info['header_size']));
        return compact('contents', 'info', 'header', 'error');#$a=1;
    }

    static function gt($x = null)
    {
    }

    static function bt($x = null)
    {
        return debug_backtrace(2);
    }

}

