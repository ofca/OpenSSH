<?php

namespace OpenSSH;

class AuthorizedKeysFile
{
    protected $path;
    protected $logs = array();
    protected $backup = true;
    protected $backupPath;

    public function __construct($file)
    {
        if ( ! file_exists($file)) {
            throw new \InvalidArgumentException(sprintf('%s file not exists.', $file));
        }

        if ( ! is_readable($file)) {
            throw new \InvalidArgumentException(sprintf('%s file is not readable.', $file));
        }

        $this->file = $file;

        $info = pathinfo($file);
        $this->backupPath = $info['dirname'].'/'.$info['filename'].'-backups/';
    }

    /**
     * Return keys from specified keys file.
     *
     * > Note: Result of this function is not cached, every time
     * > you call this method, the file is opened and parsed.
     * 
     * @return array
     */
    public function getKeys()
    {
        $keys = array();
        $i = 0;

        // Read file line by line
        foreach (file($this->file) as $line) {
            $i++;

            $line = rtrim(rtrim($line, "\n"), "\r");

            // Skip empty lines
            if ($line === '') {
                $this->log('info', 'Empty line founded at line %s', $i);
                continue;
            }

            // Skip comments
            if ($line[0] === '#') {
                $this->log('info', 'Comment founded at line %s', $i);
                continue;
            }

            try {
                $keys[] = new \OpenSSH\AuthorizedKey($line);
                $this->log('info', 'Valid key founded at line %s', $i);
            } catch (\OpenSSH\Exception\MalformedAuthorizedKey $e) {
                // Something goes wrong
                $this->log('error', 'Not valid key founded at line %s. Key has been skipped; Exception: \OpenSSH\Exception\MalformedAuthorizedKey with message: %s;', $i, $e->getMessage());
            } catch (\OpenSSH\Exception\MalformedSSHKey $e) {
                // Something goes wrong
                $this->log('error', 'Not valid key founded at line %s. Key has been skipped; Exception: \OpenSSH\Exception\MalformedSSHKey with message: %s;', $i, $e->getMessage());
            } catch (\UnexpectedValueException $e) {
                // Something goes wrong
                $this->log('error', 'Not valid key founded at line %s. Key has been skipped; Exception: \UnexpectedValueException with message: %s; Key content: %s;', $i, $line, $e->getMessage());
            }
        }

        return $keys;
    }

    public function removeKey($key, $field = 'keyString')
    {
        if (is_string($key) or $key instanceof \OpenSSH\SSHKey) {
            $key = new \OpenSSH\AuthorizedKey((string) $key);
        }

        if ( ! ($key instanceof \OpenSSH\AuthorizedKey)) {
            throw new \InvalidArgumentException('$key param should be string or instance of \OpenSSH\SSHKey or \OpenSSH\AuthorizedKey.');
        }

        $allowed = array('keyString', 'type', 'key', 'comment');

        if ( ! in_array($field, $allowed)) {
            throw new \InvalidArgumentException(sprintf('%s field is not allowed for comparison.'));
        }

        $method = 'get'.ucfirst($field);

        // Make backup before file modifications
        $this->makeBackup();

        $handle = fopen($this->file, 'r');

        if ( ! $handle) {
            throw new \Exception(sprintf('Can not open %s file.', $this->file));
        }

        if ( ! flock($handle, LOCK_EX)) {
            throw new \Exception(sprintf('Can not lock %s file.', $this->file));
        }

        $new = array();
        $removed = false;

        while (($line = fgets($handle)) !== false) {

            $line = rtrim(rtrim($line, "\n"), "\r");

            // Skip empty lines and comments
            if ($line == '' or $line[0] == '#') {
                $new[] = $line;
                continue;
            }

            try {
                $ckey = new \OpenSSH\AuthorizedKey($line);

                if ($ckey->$method() === $key->$method()) {
                    $removed = true;
                    continue;
                }
            } catch (\Exception $e) {
                $new[] = $line;
                continue;
            }

            $new[] = (string) $ckey;
        }

        $whandle = fopen($this->file, 'w');
        fwrite($whandle, implode("\n", $new));
        fflush($whandle);
        fclose($whandle);

        flock($handle, LOCK_UN);
        fclose($handle);

        return $removed;
    }

    public function insertKey($key)
    {
        if (is_string($key) or $key instanceof \OpenSSH\SSHKey) {
            $key = new \OpenSSH\AuthorizedKey((string) $key);
        }

        if ( ! ($key instanceof \OpenSSH\AuthorizedKey)) {
            throw new \InvalidArgumentException('$key param should be string or instance of \OpenSSH\SSHKey or \OpenSSH\AuthorizedKey.');
        }

        $handle = fopen($this->file, 'a');

        if ( ! $handle) {
            throw new \Exception(sprintf('Can not open %s file.', $this->file));
        }

        if ( ! flock($handle, LOCK_EX)) {
            throw new \Exception(sprintf('Can not lock %s file.', $this->file));
        }

        fwrite($handle, "\n".(string) $key);
        fflush($handle);
        flock($handle, LOCK_UN);
        fclose($handle);

        return $this;
    }    

    public function makeBackup()
    {
        if ($this->backup) {

            // Create backup directory
            if ( ! is_dir($this->backupPath)) {                
                if (mkdir($this->backupPath, 0644, true) === false) {
                    throw new \Exception(sprintf('Can not create backup directory: %s', $this->backupPath));
                }
            }

            list($msec, $sec) = explode(' ', microtime());
            $name = 
                $this->backupPath
                .sprintf('%s-%s', date('Y-m-d-H-s-i', $sec), $msec);

            if (copy($this->file, $name) === false) {
                throw new \Exception(sprintf('Can not create backup file with name %s', $name));
            }
        }
    }

    public function turnOffBackups()
    {
        $this->backup = false;
    }

    public function turnOnBackups()
    {
        $this->backup = true;
    }

    public function setBackupDirectory($path)
    {
        $this->backupPath = $path;
    }

    public function getBackupDirectory()
    {
        return $this->backupPath;
    }

    protected function log()
    {
        $args = func_get_args();
        $type = array_shift($args);
        $msg = array_shift($args);

        $this->logs[] = array($type, vsprintf($msg, $args));
    }

    public function getLogs()
    {
        return $this->logs;
    }
}