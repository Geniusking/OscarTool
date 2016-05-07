<?php
/**
 * Prevent Wordpress POST xmlrpc.php attack by block the attacker's IP address using iptables
 * Author : Geniusking
 * Date: 2016-05-05
 */

/** 'POST /xmlrpc.php' counts limit in access.log */
define("LIMITS", 50);

/** Get the IPs who POST xmlrpc.php */
$ips = shell_exec("grep 'POST /xmlrpc.php' /var/log/apache2/access.log | awk '{print $1}'");

$arr_ips = explode("\n", $ips);
$pool = array();
foreach ($arr_ips as $ip) {
    @$pool[$ip] += 1;
}

echo $iptables_list = shell_exec("/sbin/iptables -L -n");

foreach ($pool as $ip => $counts) {

    if (!empty($ip) && preg_match("/$ip/is", $iptables_list, $o) == false) {

        if ($counts > LIMITS) {
            echo $cmd = sprintf("/sbin/iptables -I INPUT -s %s -j DROP\n", $ip);
            shell_exec($cmd);
        }
    }

}

echo shell_exec("/sbin/iptables -L -n");
