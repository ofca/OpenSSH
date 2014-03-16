### What it is?

PHP classes for parsing OpenSSH authorized_keys file and more.

> NOTE: Supported is only SSH2 protocol.

### What this can do for me?

* Return all keys from `authorized_keys` file
* Insert key to `authorized_keys` file
* Remove key from `authorized_keys` file
* Validate line from `authorized_keys` file
* Return options for key (you know, like `command`, `no-port-forwarding`, `no-agent-forwarding` ect.)
* Validate plain SSH key
* Return SSH key type, "key" or comment.

### Examples

#### Validate SSH key

~~~php
try {
    $key = new \OpenSSH\SSHKey('ssh-rsa AAAAksf...sdfa== me@domain.com');
} catch (\InvalidArgumentException $e) {
    // This exception is throwed if you provide empty string (or not string), 
    // or string has some break lines inside
    echo $e->getMessage();
} catch (\OpenSSH\Exception\MalformedSSHKey $e) {
    // This exception is throwed if key is in bad format.
    echo $e->getMessage();
}
~~~

#### Validate line from `authorized_keys` file

~~~php
try {
    $key = new \OpenSSH\AuthorizedKey('command="/bin/echo hello",no-X11-forwarding,no-agent-forwarding,no-port-forwarding ssh-rsa AAAAB3NzaC...cAQ==');
} catch (\OpenSSH\Exception\MalformedAuthorizedKey $e) {
    // This exception is throwed if key is in bad format.
    echo $e->getMessage();
}
~~~

#### Get key options

~~~php
$key = new \OpenSSH\AuthorizedKey('command="/bin/echo hello",no-X11-forwarding,no-agent-forwarding,no-port-forwarding ssh-rsa AAAAB3NzaC...cAQ==');

$key->hasOption('no-X11-forwarding'); // return true
$key->hasOption('no-agent-forwarding'); // return true
$key->hasOption('tunnel'); // return false
$key->getOption('command'); // return /bin/echo hello
~~~

More examples in progress... (If you need more exampleslook at `tests`).