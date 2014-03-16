<?php

require_once 'src/OpenSSH/Exception/MalformedSSHKey.php';
require_once 'src/OpenSSH/SSHKey.php';

class SSHKeyTest extends \PHPUnit_Framework_TestCase
{
    public function testKeyStringParsing()
    {
        $key = new \OpenSSH\SSHKey();

        // Key without comment
        $key->setKeyString('ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEApKhknnVCoeey3m9m6jRR7Gslb4flytZp92gpXjLAC9nsZicLztYfsjJEN0VE1xVodovvXkb0DnLOHf6CPp8YI3tasvPxKkE/e8bQieww+q9mWTSYJRi4usRR6X5mkJ60tnzP5MpvW/QCXlITIbgDRsuPmeEGgefMCtcnvVrKaJVkijC4CBhbTg8QSA+DZ2T98SodsOxBAQFLxnzwIYaoh2zctrcvl0tufHWsgo3nHaa1Oz1e+RHDIRDWFz/fIAwmSPADwaKU14iqDQ8E9TdTVXtqtjqhrCnpqJoHCl4iUjzS00stxix4s10bUbiq0BasgNVQA4CbgnkZ6t0zob6V1cAQ==');

        $this->assertEquals('ssh-rsa', $key->getType());
        $this->assertEquals('AAAAB3NzaC1yc2EAAAABIwAAAQEApKhknnVCoeey3m9m6jRR7Gslb4flytZp92gpXjLAC9nsZicLztYfsjJEN0VE1xVodovvXkb0DnLOHf6CPp8YI3tasvPxKkE/e8bQieww+q9mWTSYJRi4usRR6X5mkJ60tnzP5MpvW/QCXlITIbgDRsuPmeEGgefMCtcnvVrKaJVkijC4CBhbTg8QSA+DZ2T98SodsOxBAQFLxnzwIYaoh2zctrcvl0tufHWsgo3nHaa1Oz1e+RHDIRDWFz/fIAwmSPADwaKU14iqDQ8E9TdTVXtqtjqhrCnpqJoHCl4iUjzS00stxix4s10bUbiq0BasgNVQA4CbgnkZ6t0zob6V1cAQ==', $key->getKey());
        $this->assertEquals(null, $key->getComment());

        // Key with comment
        $key->setKeyString('ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEApKhknnVCoeey3m9m6jRR7Gslb4flytZp92gpXjLAC9nsZicLztYfsjJEN0VE1xVodovvXkb0DnLOHf6CPp8YI3tasvPxKkE/e8bQieww+q9mWTSYJRi4usRR6X5mkJ60tnzP5MpvW/QCXlITIbgDRsuPmeEGgefMCtcnvVrKaJVkijC4CBhbTg8QSA+DZ2T98SodsOxBAQFLxnzwIYaoh2zctrcvl0tufHWsgo3nHaa1Oz1e+RHDIRDWFz/fIAwmSPADwaKU14iqDQ8E9TdTVXtqtjqhrCnpqJoHCl4iUjzS00stxix4s10bUbiq0BasgNVQA4CbgnkZ6t0zob6V1cAQ== john@doe.com');

        $this->assertEquals('ssh-rsa', $key->getType());
        $this->assertEquals('AAAAB3NzaC1yc2EAAAABIwAAAQEApKhknnVCoeey3m9m6jRR7Gslb4flytZp92gpXjLAC9nsZicLztYfsjJEN0VE1xVodovvXkb0DnLOHf6CPp8YI3tasvPxKkE/e8bQieww+q9mWTSYJRi4usRR6X5mkJ60tnzP5MpvW/QCXlITIbgDRsuPmeEGgefMCtcnvVrKaJVkijC4CBhbTg8QSA+DZ2T98SodsOxBAQFLxnzwIYaoh2zctrcvl0tufHWsgo3nHaa1Oz1e+RHDIRDWFz/fIAwmSPADwaKU14iqDQ8E9TdTVXtqtjqhrCnpqJoHCl4iUjzS00stxix4s10bUbiq0BasgNVQA4CbgnkZ6t0zob6V1cAQ==', $key->getKey());
        $this->assertEquals('john@doe.com', $key->getComment());
    }

    /**
     * @covers \OpenSSH\SSHKey::setKeyString
     * @expectedException \OpenSSH\Exception\MalformedSSHKey
     */
    public function testBadKeyExceptions()
    {
        // Bad type
        $key = new \OpenSSH\SSHKey('ssh-rsda AAAAB3NzaC1yc2EAAAABIwAAAQEApKhknnVCoeey3m9m6jRR7Gslb4flytZp92gpXjLAC9nsZicLztYfsjJEN0VE1xVodovvXkb0DnLOHf6CPp8YI3tasvPxKkE/e8bQieww+q9mWTSYJRi4usRR6X5mkJ60tnzP5MpvW/QCXlITIbgDRsuPmeEGgefMCtcnvVrKaJVkijC4CBhbTg8QSA+DZ2T98SodsOxBAQFLxnzwIYaoh2zctrcvl0tufHWsgo3nHaa1Oz1e+RHDIRDWFz/fIAwmSPADwaKU14iqDQ8E9TdTVXtqtjqhrCnpqJoHCl4iUjzS00stxix4s10bUbiq0BasgNVQA4CbgnkZ6t0zob6V1cAQ==');

        $this->assertEquals(null, $key->getType());
        $this->assertEquals(null, $key->getKey());
        $this->assertEquals(null, $key->getComment());

        // Missing AAAA on the front of the key
        $key->setKeyString('ssh-rsa AAAB3NzaC1yc2EAAAABIwAAAQEApKhknnVCoeey3m9m6jRR7Gslb4flytZp92gpXjLAC9nsZicLztYfsjJEN0VE1xVodovvXkb0DnLOHf6CPp8YI3tasvPxKkE/e8bQieww+q9mWTSYJRi4usRR6X5mkJ60tnzP5MpvW/QCXlITIbgDRsuPmeEGgefMCtcnvVrKaJVkijC4CBhbTg8QSA+DZ2T98SodsOxBAQFLxnzwIYaoh2zctrcvl0tufHWsgo3nHaa1Oz1e+RHDIRDWFz/fIAwmSPADwaKU14iqDQ8E9TdTVXtqtjqhrCnpqJoHCl4iUjzS00stxix4s10bUbiq0BasgNVQA4CbgnkZ6t0zob6V1cAQ==');

        $this->assertEquals(null, $key->getType());
        $this->assertEquals(null, $key->getKey());
        $this->assertEquals(null, $key->getComment());
    }
}