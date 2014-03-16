<?php

require_once 'src/OpenSSH/Exception/MalformedSSHKey.php';
require_once 'src/OpenSSH/Exception/MalformedAuthorizedKey.php';
require_once 'src/OpenSSH/SSHKey.php';
require_once 'src/OpenSSH/AuthorizedKey.php';
require_once 'src/OpenSSH/AuthorizedKeysFile.php';

use \OpenSSH\AuthorizedKeysFile as AuthorizedKeysFile;

class AuthorizedKeysFileTest extends \PHPUnit_Framework_TestCase
{
    /*public function testKeyStringParsing()
    {
        $key = new \OpenSSH\AuthorizedKeysFile('authorized_keys_large');

        $memory = memory_get_usage();
        $var = $key->getKeys();

        // ~10000 keys = ~65mb ram memory and parsed below 1 second
        $size = memory_get_usage() - $memory;
        $unit=array('b','kb','mb','gb','tb','pb');
        echo @round($size/pow(1024,($i=floor(log($size,1024)))),2).' '.$unit[$i];
        echo "\n";
        echo count($var), ' keys', "\n";
    }*/

    public function testReadingKeys()
    {
        // Do not modify our sample file
        copy('tests/authorized_keys', 'tests/test_authorized_keys');

        $file = new AuthorizedKeysFile('tests/test_authorized_keys');
        
        $this->assertEquals(5, count($file->getKeys()));

        unlink('tests/test_authorized_keys');
    }

    public function testRemovingKey()
    {
        // Do not modify our sample file
        copy('tests/authorized_keys', 'tests/test_authorized_keys');

        $file = new AuthorizedKeysFile('tests/test_authorized_keys');
        
        $this->assertEquals(5, count($file->getKeys()));

        $result = $file->removeKey('ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9fATWC3W2k8kEtnO8BpZysTc7xPrx+MHIBiYKVsjy7AW/wQPqmxYqB4jF12oQF0DnqmXSV5yfKwjFzFEET8rolw7F9+zh4nPgLCAU/oR31HpXWks1HoAbF/vKWdgRw3kCMHfDtio+R63RXstKQqctLXvYMDKcozDmjpsOqwiV3PW5QT7XcWQEkO36K2tH8FYzRqneeFyq2cULlXHF/pGLDqd6AzSILsmespsQypCEkVPp1nerWODNXz7ChbeMBbsU7ToUH3adMnXQUxLQcpi2eOHGWKnLLOZSqoJqjvLUTWgAKszQ0cA0l4PZ/N7V7GZb+mYupqlPhLq00xHJdkTj', 'key');

        $this->assertEquals(true, $result);

        $this->assertEquals(4, count($file->getKeys()));

        unlink('tests/test_authorized_keys');
    }

    public function testInsertingKey()
    {
        // Do not modify our sample file
        copy('tests/authorized_keys', 'tests/test_authorized_keys');

        $file = new AuthorizedKeysFile('tests/test_authorized_keys');
        
        $this->assertEquals(5, count($file->getKeys()));

        $file->insertKey('ssh-rsa AAAAB3NzsdC1yc2EAAAADAQABAAABAQC9fATWC3W2k8kEtnO8BpZysTc7xPrx+MHIBiYKVsjy7AW/wQPqmxYqB4jF12oQF0DnqmXSV5yfKwjFzFEET8rold7F9+zh4nPgLCAU/oR31HpXWks1HoAbF/vKWdgRw3kCMHfDtio+R63RXstKQqctLXvYMDKcozDmjpsOqwiV3PW5QT7XcWQEkO36K2tH8FYzRqneeFyq2cULlXHF/pGLDqd6AzSILsmespsQypCEkVPp1nerWODNXz7ChbeMBbsU7ToUH3adMnXQUxLQcpi2eOHGWKnLLOZSqoJqjvLUTWgAKszQ0cA0l4PZ/N7V7GZb+mYupqlPhLq00myKey');

        $keys = $file->getKeys();
        $this->assertEquals(6, count($keys));
        $this->assertEquals(true, strpos($keys[5], 'myKey') !== false);

        unlink('tests/test_authorized_keys');
    }
}
