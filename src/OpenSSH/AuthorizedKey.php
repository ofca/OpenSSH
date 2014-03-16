<?php

namespace OpenSSH;

class AuthorizedKey
{
    const OPTION_VALUEABLE = 'valueable';
    const OPTION_NOT_VALUEABLE = 'not-valueable';
    const OPTION_VALUE_PATTERN = '\="[^"]+"';

    /**
     * Available key options.
     * @var array
     */
    protected static $options = array(
        'cert-authority'        => self::OPTION_NOT_VALUEABLE, 
        'command'               => self::OPTION_VALUEABLE, 
        'environmen'            => self::OPTION_VALUEABLE,
        'from'                  => self::OPTION_VALUEABLE,
        'no-agent-forwarding'   => self::OPTION_NOT_VALUEABLE,
        'no-port-forwarding'    => self::OPTION_NOT_VALUEABLE,
        'no-pty'                => self::OPTION_NOT_VALUEABLE,
        'no-user-rc'            => self::OPTION_NOT_VALUEABLE,
        'no-X11-forwarding'     => self::OPTION_NOT_VALUEABLE,
        'permitopen'            => self::OPTION_VALUEABLE,
        'principals'            => self::OPTION_VALUEABLE,
        'tunnel'                => self::OPTION_VALUEABLE
    );

    protected $keyString;
    protected $keyOptions = array();
    protected $sshKey;

    public function __construct($keyString = null)
    {
        if ($keyString !== null) {
            $this->setKeyString($keyString);
        }
    }
 
    public static function getRegexPattern()
    {
        $options = array();

        foreach (self::$options as $option => $type) {
            $string = $option;

            if ($type === self::OPTION_VALUEABLE) {
                $string .= self::OPTION_VALUE_PATTERN;
            }

            $options[] = $string;
        }

        $options = sprintf('(?<options>(?:%s,?)+\s+)?', implode(',?|', $options));

        return $options.'(?<sshkey>'.\OpenSSH\SSHKey::getRegexPattern().')';
    }

    public function parse()
    {
        $key = $this->keyString;
        
        preg_match('~^'.self::getRegexPattern().'$~xi', $key, $match);

        if ( ! $match) {
            throw new \OpenSSH\Exception\MalformedAuthorizedKey(sprintf('Key can not be parsed properly. Key content: %s', $key));
        }

        // Create instance of SSH key
        $this->sshKey = new \OpenSSH\SSHKey($match['sshkey']);

        if ($match['options']) {
            $this->keyOptions = $this->parseOptions($match['options']);
        }

        return $this;
    }

    protected function parseOptions($options)
    {
        preg_match_all('~(?<option>[-a-z0-9]+)(?:\="(?<value>[^"]+)")?(,|$)~i', trim($options), $match, PREG_PATTERN_ORDER);

        // This should never happend (It just can't happend)
        if ( ! $match) {
            throw new \UnexpectedValueException();
        }

        $options = array();

        foreach ($match['option'] as $key => $option) {
            // This can't happen too but...
            // there is this Polish saying "strzeżonego pan bóg strzeże"...
            if ( ! isset(self::$options[$option])) {
                throw new \UnexpectedValueException(sprintf('Unexpected option "%s" founded.', $option));
            }

            $options[$option] = $match['value'][$key];
        }

        return $options;
    }

    public function setKeyString($string)
    {
        $this->keyOptions = array();
        $this->sshKey = null;

        // No break lines allowed inside key string
        if (preg_match('~\n|\r~', $string)) {
            throw new \InvalidArgumentException('Key is invalid. Reason: has break lines.');
        }

        // Key must be a string and can't be empty
        if ( ! is_string($string) or $string === '') {
            throw new \InvalidArgumentException('Key is invalid. Reason: Not string or is empty.');
        }

        // Key can't start with number (because key options can't start with number)
        if (preg_match('~^[0-9]+~', $string[0])) {
            throw new \InvalidArgumentException('Key is invalid. Reason: starts with number.');
        }

        $this->keyString = $string;
        $this->parse();
    }

    public function __toString()
    {
        return $this->getKeyString();
    }

    public function getKeyString()
    {
        $key = '';
        $options = '';

        if ($this->keyOptions) {
            foreach ($this->keyOptions as $option => $value) {
                $options[] = 
                    self::$options[$option] === self::OPTION_NOT_VALUEABLE 
                    ? $option 
                    : sprintf('%s="%s"', $option, $value);
            }

            $key = implode(',', $options).' ';
        }

        return $key.$this->sshKey->getKeyString();
    }

    public function getOptions()
    {
        return $this->keyOptions;
    }

    public function getOption($option, $default = null)
    {
        return $this->hasOption($option) ? $this->keyOptions[$option] : $default;
    }

    public function getSSHKey()
    {
        return $this->sshKey;
    }

    public function getKey()
    {
        return $this->sshKey->getKey();
    }

    public function getType()
    {
        return $this->sshKey->getType();
    }

    public function getComment()
    {
        return $this->sshKey->getComment();
    }

    public function hasOption($option)
    {
        return array_key_exists($option, $this->keyOptions);
    }
}