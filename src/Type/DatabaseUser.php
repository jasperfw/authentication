<?php

namespace JasperFW\Authentication\Type;

use Exception;
use JasperFW\Authentication\Exceptions\AccountLockoutException;
use JasperFW\Authentication\Exceptions\AuthenticationException;
use JasperFW\Authentication\User;
use JasperFW\DataAccess\DAO;

/**
 * Class DatabaseUser
 *
 * User authentication for user accounts stored in a local database. This class is designed to use JASPER FARM to
 * provide the database connection capabilities. This class uses PHP's built in password hashing functionality for
 * security of the password data.
 *
 * @package JasperFW\Authentication\Type
 */
class DatabaseUser extends User
{
    protected static string $authenticationTable = '';
    protected static string $userIDColumn = '';
    protected static string $usernameColumn = '';
    protected static string $passwordColumn = '';
    protected static string $emailColumn = '';
    protected static string $expirationColumn = '';
    protected static string $resetTokenColumn = '';
    protected static string $resetTokenExpirationColumn = '';

    /**
     * @param DAO    $dbc      The database connection containing the authentication database
     * @param string $username The username being authenticated
     * @param string $password The password being authenticated
     * @param array  $options  Optional arguments
     *
     * @return bool True if the user successfully authenticates
     * @throws AuthenticationException
     * @throws AccountLockoutException
     */
    public function authenticate(DAO $dbc, string $username, string $password, array $options = []): bool
    {
        // Get the password hash from the database
        $info = $this->getUserRecord($dbc, $username);

        // Verify the hash
        $valid_password = false;
        if (!empty($info)) {
            $valid_password = $this->validatePassword($password, $info['hash']);
        }
        if (false == $valid_password) {
            $this->badPassword('The username or password provided was not valid.');
            throw new AuthenticationException('The username or password provided is not valid.');
        }
        // Check the expiration
        if ($this->isExpired($info['expiration'])) {
            throw new AccountLockoutException('This account is locked.');
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
     * @param DAO    $dbc      The database connection
     * @param string $token    The token to authenticate against
     * @param string $username The username being authenticated
     *
     * @return bool True if the user is authenticated
     * @throws AuthenticationException
     */
    public function authenticateWithToken(DAO $dbc, string $token, string $username): bool
    {
        $authentication_table = static::$authenticationTable;
        $userid_column = static::$userIDColumn;
        $username_column = static::$usernameColumn;
        $reset_token_column = static::$resetTokenColumn;
        $reset_token_expiration_column = static::$resetTokenExpirationColumn;
        $params = array(':token' => $token);
        $username_sql = '';
        if ('' !== $username) {
            $username_sql = "$username_column = :username AND ";
            $params['username'] = $username;
        }

        //TODO: Move this to its own function so that it can be overridden
        $query = <<<SQL
SELECT $userid_column userid, $username_column username, $reset_token_column token, $reset_token_expiration_column tokenexp
  FROM $authentication_table
 WHERE $username_sql $reset_token_column = :token AND $reset_token_expiration_column > GETDATE()
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
        $this->isExpired = true;
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
        $authentication_table = static::$authenticationTable;
        $userid_column = static::$userIDColumn;
        $username_column = static::$usernameColumn;
        $password_column = static::$passwordColumn;
        $expiration_column = static::$expirationColumn;
        $email_column = static::$emailColumn;
        $reset_token_column = static::$resetTokenColumn;
        $reset_token_expiration_column = static::$resetTokenExpirationColumn;
        $params = array(':email' => $email_address);
        $username_sql = '';
        if ($username !== '') {
            $username_sql = "$username_column = :username AND ";
            $params[':username'] = $username;
        }
        // TODO: Move this to its own function
        $query = "SELECT $userid_column userid FROM $authentication_table WHERE $username_sql $email_column = :email";
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
            $clear_sql = ", $password_column = NULL, $expiration_column = NULL";
        }
        //TODO: Move this to its own function
        $query = <<<SQL
UPDATE $authentication_table
SET $reset_token_column = :token, 
$reset_token_expiration_column = :expiration
$clear_sql 
WHERE $userid_column = :userid
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
        $authentication_table = static::$authenticationTable;
        $reset_token_column = static::$resetTokenColumn;
        $query = "SELECT COUNT(*) thenum FROM $authentication_table WHERE $reset_token_column = :token";
        $result = $dbc->query($query, ['params' => [':token' => $token]])->toArray();
        if (count($result) > 0 && $result[0]['thenum'] < 1) return true;
        return false;
    }

    /**
     * Saves a new password for the user.
     *
     * @param DAO    $dbc          The database connection
     * @param string $new_password The new password to be set
     *
     * @return bool True if the password change is successful
     * @throws AuthenticationException
     * @throws Exception
     */
    public function updatePassword(DAO $dbc, string $new_password): bool
    {
        // Check that the password does not match the current password
        $info = $this->getUserRecord($dbc, $this->username)['hash'];
        if (null === $info) {
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
        $authentication_table = static::$authenticationTable;
        $password_column = static::$passwordColumn;
        $expiration_column = static::$expirationColumn;
        $userid_column = static::$userIDColumn;
        $reset_token_column = static::$resetTokenColumn;
        $reset_token_expiration_column = static::$resetTokenExpirationColumn;
        $hash = $this->hashPassword($new_password);
        $params = array(':pass' => $hash, ':user' => $this->userid);
        // If a max age for the password has been specified, set the expiration
        $expiration_sql = '';
        if (null !== static::$passwordMaxAge) {
            $expiration_sql = "$expiration_column = :exp,";
            $params[':exp'] = date('Y-m-d H:i:s', strtotime('+' . static::$passwordMaxAge . ' days'));
        }
        // Save the password
        $sql = <<<SQL
UPDATE $authentication_table
   SET $password_column = :pass,
       $expiration_sql
       $reset_token_column = NULL,
       $reset_token_expiration_column = NULL 
 WHERE $userid_column = :user
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
     * @param DAO    $dbc
     * @param string $username
     *
     * @return array|null
     */
    protected function getUserRecord(DAO $dbc, string $username): ?array
    {
        $authentication_table = static::$authenticationTable;
        $password_column = static::$passwordColumn;
        $expiration_column = static::$expirationColumn;
        $username_column = static::$usernameColumn;
        $userid_column = static::$userIDColumn;

        $sql = <<<MSSQL
SELECT $userid_column userid,
       $password_column hash,
       $expiration_column exp
  FROM $authentication_table
 WHERE $username_column = :username
MSSQL;
        $params = array(':username' => $username);
        $result = $dbc->query($sql, ['params' => $params])->toArray();
        if (0 == count($result)) {
            return null;
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
        if (empty($password)) {
            return false;
        }
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
        $this->loginAttempts ++;
        throw new AuthenticationException($message);
    }
}
