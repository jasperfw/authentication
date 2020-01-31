<?php

namespace JasperFW\Authentication\Type;

use Exception;
use JasperFW\Authentication\Exceptions\AccountLockoutException;
use JasperFW\Authentication\Exceptions\AuthenticationException;
use JasperFW\Authentication\User;
use JasperFW\DataInterface\DataAccess\DAO;

/**
 * Class LDAPUser
 *
 * Authentication for applications that use LDAP to authenticate users.
 *
 * @package JasperFW\Authentication\Type
 */
class LDAPUser extends User
{
    /**
     * @param DAO $dbc The database connection to authenticate against
     * @param string $username The username to authenticate
     * @param string $password The password to authenticate
     *
     * @return bool
     * @throws AccountLockoutException
     * @throws AuthenticationException
     * @noinspection PhpComposerExtensionStubsInspection
     */
    public function authenticate(DAO $dbc, string $username, string $password): bool
    {
        $username = ldap_escape($username);
        $password = ldap_escape($password);
        try {
            $username = str_replace('@'.$this->ldap_domain, '', $username);
            // Check how many times the user has attempted to log in
            try {
                //TODO: Move this to its own function
                $query = '(&(objectCategory=person)(sAMAccountName=' . $username . '))';
                $options = array('attributes' => array('badpwdcount'));
                $result = $dbc->query($query, $options)->toArray();
                $bpc = (isset($result[0]['badpwdcount'][0])) ? $result[0]['badpwdcount'][0] : 0;
                if ($bpc > self::$maxLoginAttempts) {
                    // The user has tried to log in too many times, block them
                    throw new AccountLockoutException('The account has been locked.');
                }
            } catch (AccountLockoutException $e) {
                throw $e;
            } catch (Exception $e) {
                throw new AuthenticationException('Unable to login: ' . $e->getMessage());
            }

            // Try to log in the user
            if ('' == $username || '' == $password) {
                // Make sure the username is not blank, because apparently ldap allows that
                $success = false;
            } else {
                $success = @ldap_bind($dbc->getHandle(), $username . '@' . $this->ldap_domain, $password);
                if (!$success) {
                    if (ldap_errno($dbc->getHandle()) == '49') {
                        throw new AuthenticationException('The username/password combination was not valid.');
                    } else {
                        throw new AuthenticationException('A problem occurred when authenticating your login.');
                    }
                }
            }
            // If the user was not authenticated throw an exception
            if (false === $success) {
                throw new AuthenticationException('The username/password combination was not valid.');
            }
            // The user is authenticated
            $this->username = $username;
            $this->userid = null;
            $this->userlevel = 'ldap';
            $this->levelCode = self::STAFF;
            $this->name = '';
            $this->authenticated = true;
            $this->groups = array();
            //$this->authentication_type = self::AUTH_LDAP;
            $this->isManager = false;
            // Try to get the user's groups
            $result = $dbc->query('(&(objectCategory=person)(sAMAccountName=' . $username . ')(cn=*))')->toArray();
            if (isset($result[0]['memberof'])) {
                unset ($result[0]['memberof']['count']);
                foreach ($result[0]['memberof'] as $groupstring) {
                    if (strpos($groupstring, 'OU=Medici Employees') !== false) {
                        // Only get the groups that are part of Medici Employees
                        $this->groups[] = substr($groupstring, 3, strpos($groupstring, ',') - 3);
                    }
                }
            }
            // The user logged in successfully, reset the attempt counter
            $this->loginAttempts = 0;
            return true;
        } catch (Exception $e) {
            throw new AuthenticationException($e->getMessage());
        }
    }

    /**
     * Change the password stored in the database. This is not supported for LDAP users.
     *
     * @param DAO    $dbc
     * @param string $new_password
     *
     * @return mixed
     * @throws Exception
     */
    public function updatePassword(DAO $dbc, string $new_password): bool
    {
        throw new Exception('This feature is not supported.');
    }
}