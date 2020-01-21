<?php

namespace JasperFW\JasperAuth\Type;

use JasperFW\JasperAuth\Exceptions\AuthenticationException;
use JasperFW\JasperAuth\User;
use JasperFW\JasperFarm\DataAccess\DAO;

/**
 * Class DatabaseUser
 *
 * User authentication for user accounts stored in a local database. This class is designed to use JASPER FARM to
 * provide the database connection capabilities. This class uses PHP's built in password hashing functionality for
 * security of the password data.
 *
 * @package JasperFW\JasperAuth\Type
 */
class DatabaseUser extends User
{
    protected static $auth_conn = '';
    protected static $authentication_table = '';
    protected static $userid_column = '';
    protected static $username_column = '';
    protected static $password_column = '';
    protected static $email_column = '';
    protected static $expiration_column = '';
    protected static $reset_token_column = '';
    protected static $reset_token_expiration_column = '';

    protected static $dbc;

    /**
     * @param string $username The username being authenticated
     * @param string $password The password being authenticated
     * @param DAO    $dbc      The database connection containing the authentication database
     *
     * @return bool True if the user successfully authenticates
     * @throws AuthenticationException
     */
    public function authenticate(string $username, string $password, DAO $dbc = null): bool
    {
        // Get the password hash from the database
        $info = $this->getUserRecord($dbc, $username);

        // Verify the hash
        $valid_password = false;
        if (false !== $info) {
            $valid_password = $this->validatePassword($password, $info);
        }

        if (false == $valid_password) {
            $this->badPassword('The username or password provided was not valid.');
            return false;
        }

        // If execution gets here, the user authenticated, load their information
        session_regenerate_id();
        $this->authenticated = true;
        $this->populateUserInfo($dbc);
        return true;
    }

    /**'
     * Use a pseudorandom password token to authenticate instead of a password. This is useful for a forgot password or
     * initial user signup functionality.
     *
     * @param DAO    $dbc The database connection
     * @param string $token    The token to authenticate against
     * @param string $username The username being authenticated
     *
     * @return bool True if the user is authenticated
     */
    public function authenticateWithToken(DAO $dbc, string $token, string $username): bool
    {
        $authentication_table = static::$authentication_table;
        $userid_column = static::$userid_column;
        $username_column = static::$username_column;
        $reset_token_column = static::$reset_token_column;
        $reset_token_expiration_column = static::$reset_token_expiration_column;
        $params = array(':token' => $token);
        $username_sql = '';
        if (false !== $username) {
            $username_sql = "{$username_column} = :username AND ";
            $params['username'] = $username;
        }

        //TODO: Move this to its own function so that it can be overridden
        $query = <<<SQL
SELECT {$userid_column} userid, {$username_column} username, {$reset_token_column} token, {$reset_token_expiration_column} tokenexp
  FROM {$authentication_table}
 WHERE {$username_sql}{$reset_token_column} = :token AND {$reset_token_expiration_column} > GETDATE()
SQL;

        $result = $dbc->query($query, ['params' => $params])->toArray();
        if (count($result) < 1) {
            $this->badPassword("The username and/or token provided was not valid.");
            return false;
        }
        $result = $result[0];
        $this->authenticated = true;
        $this->userid = $result['userid'];
        $this->username = $result['username'];
        $this->levelCode = static::USER;
        $this->is_expired = true;
        $this->populateUserInfo($dbc);
        return true;
    }

    /**
     * Set a token to allow or force the user to reset their password
     *
     * @param DAO $dbc The database connection where the authentication data is stored
     * @param string $email_address The user e-mail address
     * @param string $username The username
     * @param int    $token_lifespan_minutes The number of minutes before the token should expire
     * @param bool   $disable_login True to disable the password - after this, login will only be possible with the token
     *
     * @return string|null
     */
    public static function setResetToken(DAO $dbc, string $email_address, string $username, int $token_lifespan_minutes = 180, bool $disable_login = false): ?string
    {
        $authentication_table = static::$authentication_table;
        $userid_column = static::$userid_column;
        $username_column = static::$username_column;
        $password_column = static::$password_column;
        $expiration_column = static::$expiration_column;
        $email_column = static::$email_column;
        $reset_token_column = static::$reset_token_column;
        $reset_token_expiration_column = static::$reset_token_expiration_column;
        $params = array(':email' => $email_address);
        $username_sql = '';
        if ($username !== false) {
            $username_sql = "{$username_column} = :username AND ";
            $params[':username'] = $username;
        }
        // TODO: Move this to its own function
        $query = "SELECT {$userid_column} userid FROM {$authentication_table} WHERE {$username_sql}{$email_column} = :email";
        $result = $dbc->query($query, ['params' => $params])->toArray();
        if (count($result) < 1) {
            return false;
        }
        $userid = $result[0]['userid'];
        do {
            $token = static::generatePassword(25);
        } while (!static::isTokenUnique($dbc, $token));

        $token_expiration = date('Y-m-d H:i:s', strtotime('+' . $token_lifespan_minutes . ' minutes'));
        $clear_sql = '';
        if ($disable_login) {
            $clear_sql = ", {$password_column} = NULL, {$expiration_column} = NULL";
        }
        //TODO: Move this to its own function
        $query = <<<SQL
UPDATE {$authentication_table} 
SET {$reset_token_column} = :token, 
{$reset_token_expiration_column} = :expiration
{$clear_sql} 
WHERE {$userid_column} = :userid
SQL;
        $params = array(':userid' => $userid, ':token' => $token, ':expiration' => $token_expiration);
        $dbc->query($query, ['params' => $params]);
        return $token;
    }

    /**
     * Determine if the token is already set in the database
     *
     * @param DAO    $dbc The database connection
     * @param string $token The token to check
     *
     * @return bool True if the token is not already in use
     */
    protected static function isTokenUnique(DAO $dbc, string $token): bool
    {
        $authentication_table = static::$authentication_table;
        $reset_token_column = static::$reset_token_column;
        $query = "SELECT COUNT(*) thenum FROM {$authentication_table} WHERE {$reset_token_column} = :token";
        $result = $dbc->query($query, ['params' => [':token' => $token]])->toArray();
        if (count($result) > 0 && $result[0]['thenum'] < 1) return true;
        return false;
    }

    /**
     * Saves a new password for the user.
     * @param DAO $dbc The database connection
     * @param string $new_password The new password to be set
     * @return bool True if the password change is successful
     * @throws AuthenticationException
     * @throws \Exception
     */
    public function updatePassword(DAO $dbc, string $new_password): bool
    {
        // Check that the password does not match the current password
        $info = $this->getUserRecord($dbc, $this->username);
        if (false === $info) {
            throw new AuthenticationException('You are not authorized to change this password.');
        }
        if ($this->validatePassword($new_password, $info)) {
            throw new AuthenticationException('Must enter a new password.');
        }

        // Make sure the password matches the complexity rules
        if (false === static::checkComplexity($new_password)) {
            throw new AuthenticationException('The entered password does not match the complexity requirements');
        }
        // Set the params
        $authentication_table = static::$authentication_table;
        $password_column = static::$password_column;
        $expiration_column = static::$expiration_column;
        $userid_column = static::$userid_column;
        $reset_token_column = static::$reset_token_column;
        $reset_token_expiration_column = static::$reset_token_expiration_column;
        $hash = $this->hashPassword($new_password);
        $params = array(':pass' => $hash, ':user' => $this->userid);
        // If a max age for the password has been specified, set the expiration
        $expiration_sql = '';
        if (null !== static::$password_max_age) {
            $expiration_sql = "{$expiration_column} = :exp,";
            $params[':exp'] = date('Y-m-d H:i:s', strtotime('+' . static::$password_max_age . ' days'));
        }
        // Save the password
        $sql = <<<SQL
UPDATE {$authentication_table}
   SET {$password_column} = :pass,
       {$expiration_sql}
       {$reset_token_column} = NULL,
       {$reset_token_expiration_column} = NULL 
 WHERE {$userid_column} = :user
SQL;
        $dbc->query($sql, ['params' => $params]);
        return true;
    }

    /**
     * Hash the password, using PHP's built in hash utility
     * @param string $password The password to hash
     * @return string The hashed version of the password
     */
    public function hashPassword(string $password): string
    {
        return password_hash($password, PASSWORD_DEFAULT);
    }

    /**
     * Get the hashed password from the database.
     *
     * @param DAO $dbc
     * @param $username
     * @return string
     */
    protected function getUserRecord(DAO $dbc, string $username): string
    {
        $authentication_table = static::$authentication_table;
        $password_column = static::$password_column;
        $expiration_column = static::$expiration_column;
        $username_column = static::$username_column;
        $userid_column = static::$userid_column;

        $sql = <<<MSSQL
SELECT {$userid_column} userid,
       {$password_column} hash,
       {$expiration_column} exp
  FROM {$authentication_table}
 WHERE {$username_column} = :username
MSSQL;
        $params = array(':username' => $username);
        $result = $dbc->query($sql, ['params' => $params])->toArray();
        if (0 == count($result)) {
            return false;
        }
        return $result[0];
    }

    /**
     * Check if the password matches the hash.
     *
     * @param string $password
     * @param string $hash
     * @return bool
     */
    protected function validatePassword(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * Retrieves and sets additional values about the user beyond authentication status and username.
     * @param DAO $dbc
     */
    protected function populateUserInfo(DAO $dbc): void
    {

    }

    /**
     * Checks if the login information is expired.
     * @param string $expiration_date The expiration date from the database
     * @return bool True if it is expired
     */
    protected function isExpired(string $expiration_date): bool
    {
        return (strtotime($expiration_date) < time());
    }

    /**
     * Handles a bad password
     * @param string $message The error message to return
     * @throws AuthenticationException
     */
    protected function badPassword(string $message = 'The username or password provided were not valid.'): void
    {
        $this->login_attempts ++;
        throw new AuthenticationException($message);
    }
}