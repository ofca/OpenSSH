<?php

namespace OpenSSH;

/**
 * SSH2 key parser.
 *
 * @author Tomasz Zeludziewicz <ofca@emve.org>
 */
class SSHKey
{
    /**
     * Long, long string without white spaces.
     * @var string
     */
    protected $key;

    /**
     * Key type (available types are defined in SSHKey::$keyTypes).
     * @var string
     */
    protected $type;

    /**
     * Key comment (optional).
     * @var string
     */
    protected $comment;

    /**
     * Key string in SSH2 format, for example:
     *
     *     ssh-rsa AAAAkKdfwjl...jK8LSDf== optional comment
     * 
     * @var string
     */
    protected $keyString;

    /**
     * Available key types.
     * @var array
     */
    protected static $keyTypes = array('ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'ssh-ed25519', 'ssh-dss', 'ssh-rsa');

    /**
     * Constructor parse specified key and resolve if is valid.
     *
     * Note: Key string can not contains break lines!
     * 
     * @param string $keyString Key string (optional).
     */
    public function __construct($keyString = null)
    {
        if ($keyString !== null) {
            $this->setKeyString($keyString);
        }
    }

    public function parse()
    {
        preg_match('~^'.static::getRegexPattern().'$~xi', $this->keyString, $match);

        if ( ! $match) {
            throw new \OpenSSH\Exception\MalformedSSHKey(sprintf('Key can not be parsed properly. Key content: %s', $this->keyString));
        }

        $this->type = $match['type'];
        $this->key = $match['key'];

        if (isset($match['comment'])) {
            $this->comment = trim($match['comment']);
        }

        return $this;
    }

    public static function getRegexPattern()
    {
        return '
            (?<type>'.implode('|', self::$keyTypes).')\s+ # key type
            (?<key>AAAA[^\s|$]+)                          # key (key starts always with 4 A chars)
            (?<comment>[^$]+)?                            # optional comment
        ';
    }

    /**
     * Parse specified key and resolve if is valid.
     *
     * Note: Key string can not contains break lines!
     * 
     * @param string $keyString Key string.
     */
    public function setKeyString($string)
    {
        // Reset
        $this->type = null;
        $this->key = null;
        $this->comment = null;

        // Key must be a string and can't be empty
        if ( ! is_string($string) or $string === '') {
            throw new \InvalidArgumentException('Specified key is not string or is empty.');
        }

        // No break lines allowed inside key string
        if (preg_match('~\n|\r~', $string)) {
            throw new \InvalidArgumentException('Specified key has break lines.');
        }   

        $this->keyString = $string;
        $this->parse();

        return $this;
    }

    public function __toString()
    {
        return $this->getKeyString();
    }

    public function getKeyString()
    {
        $key = sprintf('%s %s', $this->type, $this->key);

        if ( ! empty($this->comment)) {
            $key .= sprintf(' %s', $this->comment);
        }

        return $key;
    }

    public function getType()
    {
        return $this->type;
    }

    public function getKey()
    {
        return $this->key;
    }

    public function getComment()
    {
        return $this->comment;
    }
}