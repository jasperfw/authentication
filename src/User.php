<?php

namespace WigeDev\JasperAuth;

use Exception;
use WigeDev\JasperAuth\Exceptions\AccountLockoutException;
use WigeDev\JasperAuth\Exceptions\AuthenticationException;
use WigeDev\JasperFarm\DataAccess\DAO;

/**
 * Class User
 *
 * The abstract user class represents a single user. This class can be extended by an appropriate user type class such
 * as LDAPUser or DatabaseUser, depending on the source the user credentials will be authenticated against.
 *
 * @package WigeDev\JasperAuth
 */
abstract class User
{
    // Parameters for passwords
    /** @var int The minimum number of characters for a password to be considered valid */
    protected static $password_min_characters = 8;
    /** @var null|int The maximum number of characters for a password to be considered valid - set null if there is no max */
    protected static $password_max_characters = null;
    /** @var bool True if the password must contain at least one letter */
    protected static $password_require_letter = true;
    /** @var bool True if the password must contain at least one number */
    protected static $password_require_digit = true;
    /** @var bool True if the password must contain at least one special character */
    protected static $password_require_special = false;
    /** @var null|int The age in days before a new password must be created. Set to null if no expiration is required */
    protected static $password_max_age = null;

    /** @var User Single reference to the User object */
    protected static $_instance;
    protected static $max_login_attempts = 3;
    protected static $encKey = 'superSecretEncKey';
    /** @var string The name of the session variable this object will be serialized into */
    protected static $session_name = 'session_user';

    // User levels
    /** An unauthenticated user */
    const GUEST = 0;
    /** An authenticated user */
    const USER = 1;
    /** An authenticated user who works for Medici */
    const STAFF = 2;
    /** An authenticated user who is an admin at Medici */
    const ADMINISTRATOR = 3;

    /** @var string[] Array of error messages generated during the login process */
    protected $errors = [];
    /** @var int The number of times the user has attempted to log in */
    protected $login_attempts;

    // Information about the account
    protected $username;
    protected $userid;
    protected $userlevel;
    protected $name;
    protected $authenticated;
    protected $authentication_method;
    protected $levelCode;
    protected $is_expired;
    protected $groups;
    protected $is_manager;
    // Information about the user, for preventing session hijacking
    protected $ipaddress;
    protected $useragent;

    /**
     * Returns a reference to the single user object. If the user object has
     * already been created, that object is returned. Otherwise, the object will be created from
     * the session if it exists. If a user object has not been serialized, then a new object will be
     * created.
     */
    public static function i(): User
    {
        // Check if a user object has been created
        if (!isset(static::$_instance)) {
            // Check if the object is stored in the user session
            if (isset($_SESSION[static::$session_name])) {
                static::$_instance = unserialize($_SESSION[static::$session_name]);
                //unset($_SESSION['session_user']);
            } else {
                $c = get_called_class();
                static::$_instance = new $c;
            }
        }
        return static::$_instance;
    }

    /**
     * Check that the password meets the complexity requirements.
     *
     * @param $new_password
     * @return bool
     */
    public static function checkComplexity($new_password): bool
    {
        if (strlen($new_password) < static::$password_min_characters) {
            return false;
        }
        if (static::$password_max_characters != null && strlen($new_password) > static::$password_max_characters) {
            return false;
        }
        if (static::$password_require_letter && !preg_match('/[A-Za-z]/', $new_password)) {
            return false;
        }
        if (static::$password_require_digit && !preg_match('/[0-9]/', $new_password)) {
            return false;
        }
        if (static::$password_require_special && !preg_match('/[^A-Za-z0-9]/', $new_password)) {
            return false;
        }
        return true;
    }

    /**
     * For use with a password generator, this function will generate a new password if needed. Creates an alphanumeric
     * password of the specified length, or eight characters by default.
     *
     * @param int $length The number of characters for the password.
     * @return string The generated password.
     */
    public static function generatePassword(int $length = 8): string
    {
        $pass = '';
        $salt = "abcdefghijklmnopqrstuvwxyz0123456789";
        srand((double)microtime() * 1000000);
        $i = 1;
        while ($i <= $length) {
            $num = rand() % 33;
            $tmp = substr($salt, $num, 1);
            $pass = $pass . $tmp;
            $i++;
        }
        return $pass;
    }

    /**
     * The constructor will create the user object provided that the user authenticates properly
     */
    protected function __construct()
    {
        // Set the visitor's information
        $this->ipaddress = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
        $this->useragent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
        // Set the default information
        $this->clear();
        $this->login_attempts = 0;
    }

    /**
     * Since the object will be unserialized at page load, the user information should be checked at
     * that time to prevent session hijacking.
     *
     * NOTE: The session checking is currently disabled, as mobile users may change IP Address unexpectedly. This is
     * still being researched.
     */
    public function __wakeup(): void
    {
        // First, check that the user agent has not changed
        //if ($_SERVER['HTTP_USER_AGENT'] != $this->useragent) {
        //    $_SERVER['HTTP_USER_AGENT'] = $this->useragent;
        //    echo '<p>Your user agent has changed! This may be due to an attempt to hijack your session.</p>' . "\n\n";
        //    \Framework::i()->view->renderer->setSuccess(false);
        //} elseif ($_SERVER['REMOTE_ADDR'] != $this->ipaddress) {
        //    $_SERVER['REMOTE_ADDR'] = $this->ipaddress;
        //    $this->clear();
        //    echo '<p>Your IP Address has changed! This may be due to an attempt to hijack your session.</p>' . "\n\n";
        //}
        //$this->ipaddress = $_SERVER['REMOTE_ADDR'];
        //$this->useragent = $_SERVER['HTTP_USER_AGENT'];
    }

    /**
     * When the object is destroyed (ie, when the page completes rendering) this function is called
     * and will serialize the object. This should not be done by any other function.
     */
    public function __destruct()
    {
        $_SESSION[static::$session_name] = serialize(self::$_instance);
    }

    /**
     * Prevent information leak by overriding the default __toString and simply return the username.
     * @return string The username
     */
    public function __toString(): string
    {
        return $this->getUsername();
    }

    /**
     * Get the username.
     * @return string The username
     */
    public function getUsername(): ?string
    {
        return $this->username;
    }

    /**
     * Set allows values to be set. Since none of the internal values can be set however, this simply
     * ignores the incoming data. This function exists to prevent overriding.
     *
     * @param string $index The name of the variable being set
     * @param mixed  $value The value to be set
     *
     * @return void
     */
    public function __set($index, $value): void
    {
        return;
    }

    /**
     * Get allows values to be retrieved. Only some of the contained values can be revealed however.
     *
     * @param string $index The name of the variable to be retrieved
     *
     * @return mixed The value associated with the index
     */
    public function __get($index)
    {
        // Determine which value to return
        switch ($index) {
            case 'username':
                return $this->username;
            case 'id':
                return $this->userid;
            case 'name':
                if ($this->name == null) {
                    return 'Guest';
                } else {
                    return $this->name;
                }
            case 'errors':
                return $this->errors;
            case 'level':
                return $this->levelCode;
//            case 'authentication_type':
//                return $this->authentication_type;
            case 'groups':
                return $this->groups;
            case 'is_expired':
                return $this->is_expired;
            default:
                return null;
        }
    }

    /**
     * The logout function allows users to logout by reinitializing the user object.
     */
    public function logout(): void
    {
        $this->clear();
    }

    /**
     * The clear function zeroes out any stored data.
     */
    protected function clear(): void
    {
        // Set the default information
        $this->username = null;
        $this->userid = null;
        $this->userlevel = 'guest';
        $this->levelCode = self::GUEST;
        $this->name = null;
        $this->authenticated = false;
        $this->groups = array();
        $this->is_manager = false;
    }

    /**
     * Attempt authentication against the database or service.
     * @param string $username The username
     * @param string $password
     * @param DAO $dbc The database connection
     *
     * @return bool True if the user authenticated
     * @throws AccountLockoutException
     * @throws AuthenticationException
     * @throws Exception
     */
    abstract public function authenticate(DAO $dbc, string $username, string $password): bool;

    /**
     * Check if the user has successfully authenticated.
     *
     * @return bool True if the user is authenticated
     */
    public function isAuthenticated(): bool
    {
        return $this->authenticated;
    }

    /**
     * Change the password stored in the database
     *
     * @param DAO    $dbc The database to be altered
     * @param string $new_password The new password
     *
     * @return bool True if the update succeeded
     */
    abstract public function updatePassword(DAO $dbc, string $new_password): bool;

    /**
     * Function checks if the user is in the specified group.
     *
     * @param  array|string $group The id of the group or groups to check
     *
     * @return boolean True if the user is in the specified group, false otherwise.
     */
    public function inGroup($group)
    {
        // If a string is given, convert to array
        if (!is_array($group)) {
            $group = [$group];
        }
        // If the user is in one of the groups, return true
        foreach ($group as $test) {
            if (in_array($test, $this->groups)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Set the id of the user
     * @return int The id of the user
     */
    public function getUserID(): int
    {
        return $this->userid;
    }

    /**
     * Returns an array of groups the user is in.
     *
     * @return string[] Array of groups to which the user belongs.
     */
    public function getGroups(): array
    {
        return $this->groups;
    }
}