<?php

require_once 'src/OpenSSH/Exception/MalformedAuthorizedKey.php';
require_once 'src/OpenSSH/Exception/MalformedSSHKey.php';
require_once 'src/OpenSSH/AuthorizedKey.php';

class AuthorizedKeyTest extends \PHPUnit_Framework_TestCase
{
    public function testKeyStringParsing()
    {
        $key = new \OpenSSH\AuthorizedKey();

        $key->setKeyString('command="/bin/echo hello",no-X11-forwarding,no-agent-forwarding,no-port-forwarding ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEApKhknnVCoeey3m9m6jRR7Gslb4flytZp92gpXjLAC9nsZicLztYRjJEN0VE1xVodovvXkb0DnLOHf6CPp8Yd3tasvPxKkE/e8bQieww+q9mWTSYJRi4usRR6X5mkJ60tnzPasdfW/QCXlITIbgDRsuPmeEGgefMCtcnvVrKaJVkijC4CBhbTg8QSA+DZ2T98SoWOxBAQFLxnzwIsadfaoh2zctrcvl0tufHWsgo3nHaaasOz1e+RHDIRDWFz/fIAwmSPADwaKU14iqDQ8E9TdTVXtqtjqhrCnpqJoHCl4iUjzS00stxix4s10bUbiq0BasgNVQA4CbgnkZ6t0zob6V1cAQ==');

        $this->assertEquals(true, $key->hasOption('command'));
        $this->assertEquals('/bin/echo hello', $key->getOption('command'));
        $this->assertEquals(true, $key->hasOption('no-port-forwarding'));
        $this->assertEquals(true, $key->getSSHKey() instanceof \OpenSSH\SSHKey);
    }
}