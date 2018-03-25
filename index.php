<?php

	require_once('databaseMysqli.inc.php');

	$db = new DatabaseMysqli();

	if ( $_SERVER['REQUEST_METHOD'] === 'GET' )
	{

		echo 'You submitted a GET request.<br>';

		if ( $_GET['url'] === 'auth' )
		{
			echo 'The url requested by GET was auth.<br>';
		} else if ( $_GET['url'] === 'users' )
		{
			echo 'The url requsted by GET was users.<br>';
		}

	} else if ( $_SERVER['REQUEST_METHOD'] === 'POST' )
	{

		echo 'You submitted a POST request.<br>';

		if ( $_GET['url'] === 'auth' )
		{
			echo 'The url requested by POST was auth.<br>';
			$postBody = file_get_contents('php://input');
			$postBody = json_decode($postBody);
			
			$username = $postBody->username;
			$password = $postBody->password;

			if ( $db->select('SELECT username FROM users WHERE username = ?', [$username], ['s'])[0]['username'] )
			{
				if ( password_verify($password, $db->select('SELECT password FROM users WHERE password = ?', [$password], ['s'])[0]['password']) )
				{
					$cstrong = true;
					$token = bin2hex(openssl_random_pseudo_bytes(64, $cstrong));
					$user_id = $db->select('SELECT id FROM users WHERE username = ?', [$username], ['s'])[0]['id'];
					$db->insert('login_tokens', ['', sha1($token), $user_id], ['s', 's', 'd']);
					echo '{ "Token": "' . $token . '" }';
				} else
				{
					echo 'Invalid credentials used for auth.<br>';
					http_response_code(401);
				}
			} else
			{
				echo 'Invalid credentials usesd for auth.<br>';
				http_response_code(401);
			}
		}

	} else if ( $_SERVER['REQUEST_METHOD'] === 'PUT' )
	{

		echo 'You submitted a PUT request.<br>';

	} else if ( $_SERVER['REQUEST_METHOD'] === 'DELETE' )
	{

		echo 'You submitted a DELETE request.<br>';
		if ( $_GET['url'] === 'auth' )
		{
			if ( isset($_GET['token']) )
			{
				if ( $db->delete('login_tokens', 'token', sha1($_GET['token'])) )
				{
					echo '{ "status": "success" }';
				} else
				{
					echo '{ "error": "invalid token" }';
					http_response_code(400);
				}
			} else
			{
				echo '{ "error": "mal-formed request" }';
				http_response_code(400);
			}
		}

	} else
	{

		echo 'The REQUEST_METHOD: ' . $_SERVER['REQUEST_METHOD'] . ' is not supported.<br>';
		http_response_code(405);

	}

?>