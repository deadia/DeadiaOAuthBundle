<?php

namespace Deadia\OAuthBundle\Server;

class OAuth2Server
{

	const INPUT_POST = 0;
	const INPUT_GET = 1;
	
	private $oauth;
	
	public function __construct()
	{
		$this->oauth = new HypertableOAuth;
		
	}
	
	private function getInput($type, $name)
	{
		if ($type != INPUT_POST && $type != INPUT_GET)
			return NULL;
		if ($type == INPUT_POST)
			$data = $_POST;
		else if ($type == INPUT_GET)
			$data = $_GET;
		if (isset($data[$name]))
			return $data[$name];
		return NULL;
	}
	
	private function error()
	{
	    $result = "WWW-Authenticate: OAuth realm='service'";
	    	
	    header("HTTP/1.1 400 Bad Request");
	    header($result);
	    exit();

	}
	
	public function verifyAccessToken()
	{	
		
		echo $token = $this->getInput(INPUT_POST, 'access_token');
		if (is_null($token))
			return $this->error();
		$check = $this->oauth->getAccessToken($token);
		
		if (!$check)
			return $this->error();
		return json_encode(array('access' => 'grant'));
		
	}
	
	public function grantAccessToken()
	{
		$client_id = $this->getInput(INPUT_POST, 'client_id');
		$client_secret = $this->getInput(INPUT_POST, 'client_secret');
		$check = $this->oauth->checkClientCredentials($client_id, $client_secret);
		if (!$check)
			return $this->error();
		echo "ok";
		return $this->generateToken($client_id, $client_secret);
	}
	
	private function generateToken($client_id, $client_secret)
	{
		$token = uniqid(uniqid());
		$this->oauth->setAccessToken($token, $client_id, time() + 1000, 'rest');
		return $token;
	}
}
