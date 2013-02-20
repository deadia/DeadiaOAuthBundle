<?php

namespace Deadia\OAuth2;


/**
 * OAuth2 Library PDO DB Implementation.
 */
class HypertableOAuth2 extends OAuth2 {

  private $db;

  /**
   * Overrides OAuth2::__construct().
   */
  public function __construct() {
    parent::__construct();

    try {
      $this->db = new \Deadia\HypertableBundle\Driver\Driver;
    } 
    catch (\Deadia\Driver\Exception $e) {
      die('Connection failed: ' . $e->getMessage());
    }
  }

  /**
   * Release DB connection during destruct.
   */
  function __destruct() {
    $this->db = NULL; // Release db connection
  }

   /**
   * Handle Hypertable	 exceptional cases.
   */
  private function handleException($e) {
    echo "Database error: " . $e->getMessage();
    exit;
  }
  /**
   * Little helper function to add a new client to the database.
   *
   * Do NOT use this in production! This sample code stores the secret
   * in plaintext!
   *
   * @param $client_id
   *   Client identifier to be stored.
   * @param $client_secret
   *   Client secret to be stored.
   * @param $redirect_uri
   *   Redirect URI to be stored.
   */
  public function addClient($client_id, $client_secret, $redirect_uri) {
    try {
    	$this->db->insert()->setTable('clients')
      					   ->setCell($client_id, 'clientSecret', $client_secret)
      					   ->setCell($client_id, 'redirectUri', $redirect_uri)
      					   ->execute();
    } 
    catch (\Deadia\Driver\Exception $e) {
    	$this->handleException($e);
    }
  }

  /**
   * Implements OAuth2::checkClientCredentials().
   *
   * Do NOT use this in production! This sample code stores the secret
   * in plaintext!
   */
  public function checkClientCredentials($client_id, $client_secret = NULL) {
    try {
      $client = $this->db->select()->setTable('clients')
		                           ->condition(\Deadia\Driver\Condition::ROW_EQUAL, $client_id)
		                           ->execute();
	  
      if (!isset($client[$client_id]) || $client[$client_id]->clientSecret != $client_secret)
      	return false;
      return true;
    } 
    catch (\Deadia\Driver\Exception $e) {
      $this->handleException($e);
    }
  }

  /**
   * Implements OAuth2::getRedirectUri().
   */
  public function getRedirectUri($client_id) {
    try {
    	$client = $this->db->select()->setTable('clients')
    								 ->setColumn('redirectUri')
    							     ->condition(\Deadia\Driver\Condition::ROW_EQUAL, $client_id)
    							     ->execute();
       if (!isset($client[$client_id]))
          return FALSE;
      $client = $client[$client_id];
    
      return isset($client->redirectUri) && $client->redirectUri ? $client->redirectUri : NULL;
    } catch (\Deadia\Driver\Exception $e) {
      $this->handleException($e);
    }
  }

  /**
   * Implements OAuth2::getAccessToken().
   */
  public function getAccessToken($oauth_token) {
  	echo "token";
    try {
    
      $token = $this->db->select()->setTable('tokens')
    							   ->condition(\Deadia\Driver\Condition::ROW_EQUAL, $oauth_token)
    							   ->execute();
      if (!isset($token) || !isset($token[$oauth_token]))	
      	return NULL;
      
      return $token[$oauth_token];
    } 
    catch (\Deadia\Driver\Exception $e) {
      $this->handleException($e);
    }
  }

  /**
   * Implements OAuth2::setAccessToken().
   */
  public function setAccessToken($oauth_token, $client_id, $expires, $scope = NULL) {
    try {
      $this->db->insert()->setTable('tokens')
      					 ->setCell($oauth_token, 'clientId', $client_id)
      					 ->setCell($oauth_token, 'expires', $expires)
      					 ->setCell($oauth_token, 'scope', $scope)
      					 ->execute();
    } 
    catch (\Deadia\Driver\Exception $e) {
      $this->handleException($e);
    }
  }

  /**
   * Overrides OAuth2::getSupportedGrantTypes().
   */
  public function getSupportedGrantTypes() {
    return array(
      OAUTH2_GRANT_TYPE_AUTH_CODE,
    );
  }

  /**
   * Overrides OAuth2::getAuthCode().
   */
  public function getAuthCode($code_id) {
    try {
      	$code = $this->db->select()->setTable('authCodes')
    							   ->condition(\Deadia\Driver\Condition::ROW_REGEXP, $code_id)
    							   ->execute();
    	if (!isset($code) && isset($code[$code_id]))	
      		return NULL;
   
      	return $code[$code_id];
      } 
      catch (\Deadia\Driver\Exception $e) {
      	$this->handleException($e);
    }
  }

  /**
   * Overrides OAuth2::setAuthCode().
   */
  public function setAuthCode($code, $client_id, $redirect_uri, $expires, $scope = NULL) {
    try {
    
    	 $this->db->insert()->setTable('authCodes')
      					 ->setCell($code, 'clientId', $client_id)
      					 ->setCell($code, 'expires', $expires)
      					 ->setCell($code, 'scope', $scope)
      					 ->setCell($code, 'redirectUri', $redirect_uri)
      					 ->execute();
      					 
     } catch (\Deadia\Driver\Exception $e) {
      	$this->handleException($e);
    }
  }
}
