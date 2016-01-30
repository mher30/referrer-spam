<?php
/**
 * Storing the information in a SQL-Database would be overkill,
 * so we simply save it in a json-file.
 */

/**
 * if our json-file doesn't exists we create it as an empty array, otherwise we load it into our array
 */
if (!file_exists('blacklist.json')) {
    $blacklist = array();
    file_put_contents('blacklist.json',json_encode($blacklist));
} else {
    $blacklist = json_decode(file_get_contents('blacklist.json'),true);
}

// Save the current time in a variable.
$tstamp = time();

/**
 * next we load the spammers.txt list we pulled from the GIT-repository
 */
$newlist = file('../referrer-spam-blacklist/spammers.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

$regexspecialchars = array('\\', '.', '[', ']', '(', ')', '{', '}', '+', '*');
$escaped = array ('\\\\', '\\.', '\\[', '\\]', '\\(', '\\)', '\\{', '\\}', '\\+', '\\*');

/**
 * Step through the newly pulled blacklist, domain by domain, and check if we already know that domain, 
 * and if not add it a) to our blacklist and b) to the list of newly discovered domains
 * plus we create a complete new version of apache referrer-spamblocking
 */
$regex = '';
$nginxblock = $spamblock = array();
$newdomains = array();

foreach($newlist as $domain) {
    if (!array_key_exists($domain,$blacklist)) {
	$blacklist[$domain]['firstseen'] = $tstamp; // Save it + when we have learned about this domain being a spammer-domain
	$newdomains[] = $domain;
    } 
    $blacklist[$domain]['lastseen'] = $tstamp; // Save when we have seen it the last time in the pulled spammers.txt
    $dom = str_replace($regexspecialchars,$escaped,$domain);
    if ((strlen($regex)+strlen($dom)) <= 220) {
	if ($regex === '') {
	    $regex = $dom;
	} else {
	    $regex .= '|'.$dom;
	}
    } else {
	$spamblock[] = 'RewriteCond %{HTTP_REFERER} ('.$regex.')';
	$nginxblock[] = 'if ($http_referer ~ "('.$regex.')") {'."\n\t".'set $prohibited = "1";'."\n}";
	$regex = $dom;
    }
}

if (count($newdomains) === 0)
    exit(0); // no new domains found, why continue?


$spamblock[] = 'RewriteCond %{HTTP_REFERER} ('.$regex.')';
$htaccessheader = "# Quelle Spamdomains: https://github.com/piwik/referrer-spam-blacklist/blob/master/spammers.txt\n# Quelle Apache Code: http://linuxconfig.org/how-to-block-a-referer-spam-traffic-with-apache-webserver\# Quelle: http://www.mher.de/referrer-spam/ \nn##\n\n";
$spamblockconfheader = $htaccessheader."RewriteEngine on\n";
$rulebody = implode(" [NC,OR]\n",$spamblock)." [NC]\nRewriteRule .* - [F]\n";

$rule = $spamblockconfheader.$rulebody;

$htacces = $htaccessheader.$rulebody;

$nginxblockheader = "##\n# Referrer exclusions\n# Quelle Spamdomains: https://github.com/piwik/referrer-spam-blacklist/blob/master/spammers.txt\n# Quelle: http://www.mher.de/referrer-spam/ \n##\n\n";
$nginxblock[] = 'if ($http_referer ~ "('.$regex.')") {'."\n\t".'set $prohibited = "1";'."\n}";
$nginxrule = $nginxblockheader.implode("\n\n",$nginxblock)."\n\nif (\$prohibited) {\n\treturn 403;\n}\n";

/**
 * Now we create the filter regex for Google Analytics for the newly added domains
 */

$filter = '';
$filters = array();
$domaincounter = 0;


foreach($newdomains as $domain) {
    // replace all regex-special-chars
    $domain = str_replace($regexspecialchars,$escaped,$domain);
    if ((strlen($filter)+strlen($domain)) <= 254) {
	if ($filter === '') {
	    $filter = $domain;
	} else {
	    $filter .= '|'.$domain;
	}
    } else {
	$filters[] = $filter;
	$filter = $domain;
    }
    $domaincounter++;
}
$filters[] = $filter;

// add the new filters to the filters.txt file
file_put_contents('filters.txt',implode("\n",$filters)."\n",FILE_APPEND);
// save the new filters in an extra file only containing the new filters
file_put_contents('newfilters.txt',implode("\n",$filters));
// write the new htaccess.txt file
file_put_contents('htaccess.txt',$htaccess);
// write the new apache spamblock.conf
file_put_contents('apache-spamblock.conf',$rule);
// write the new nginx referer-spam.conf
file_put_contents('nginx-spamblock.conf',$nginxrule);
// save the array of all domains in an json-file
file_put_contents('blacklist.json',json_encode($blacklist));


// Create a string with the current date
$today = date('Y-m-d');

// save the filters.txt file with the current datestamp
copy('filters.txt','filters-'.$today.'.txt');
// save the newfilters.txt with the current datestamp
copy('newfilters.txt','newfilters-'.$today.'.txt');
// save the htaccess.txt file with the current datestamp
copy('htaccess.txt', 'htaccess-'.$today.'.txt');
// save the spamblock.conf with the current datestamp
copy('apache-spamblock.conf','apache-spamblock-'.$today.'.conf');
// save the spam-filer.conf with the current datestamp
copy('nginx-spamblock.conf','nginx-spamblock-'.$today.'.conf');
// save our json-file with the current datestamp
copy('blacklist.json','blacklist-'.$today.'.json');

// echo the results
echo $domaincounter.' new domains in '.count($filters).' new filterrules defined'."\n";
