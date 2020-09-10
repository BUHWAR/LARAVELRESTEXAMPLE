<?php

namespace App\Http\Controllers;

use App\Notifications\SignupActivate;
use App\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;

//https://programacionymas.com/blog/como-enviar-mails-correos-desde-laravel
//https://medium.com/@cvallejo/sistema-de-autenticaci%C3%B3n-api-rest-con-laravel-5-6-240be1f3fc7d
class AuthController extends Controller
{
	public function signup(Request $request)
	{
		// $validate=$request->validate([
		// 	'name'     => 'required|string',
		// 	'email'    => 'required|string|email|unique:users',
		// 	'password' => 'required|string|confirmed',
		// ]);

		$validator = Validator::make($request->all(), [
			'name'     => 'required|string',
			'email'    => 'required|string|email|unique:users',
			'password' => 'required|string|confirmed',
		]);

		if ($validator->fails()) {
           //pass validator errors as errors object for ajax response
           //return response()->json(['errors'=>$validator->errors()]);
			
			//422 RESPONSE NOT COMPATIBLE WITH VOLLEY
			//return response()->json($validator->errors(),422);

			// return response()->json($validator->errors(),201);

			return response()->json($validator->errors());
		}

		$user = new User([
			'name'     => $request->name,
			'email'    => $request->email,
			'password' => bcrypt($request->password),
			'activation_token'  => Str::random(60),
		]);

		$user->save();

		$user->notify(new SignupActivate($user));

		return response()->json([
			'message' => 'Successfully created user!'], 201);
	}

	public function signupActivate($token)
	{
		$user = User::where('activation_token', $token)->first();
		if (!$user) {
			return response()->json(['message' => 'El token de activación es inválido'], 404);
		}
		$user->active = true;
		$user->activation_token = '';
		$user->save();
		return $user;
	}
	
	public function login(Request $request)
	{
		$request->validate([
			'email'       => 'required|string|email',
			'password'    => 'required|string',
			'remember_me' => 'boolean',
		]);

		$credentials = request(['email', 'password']);

		$credentials['active'] = 1;
		$credentials['deleted_at'] = null;
		
		if (!Auth::attempt($credentials)) {
			//401 RESPONSE NOT COMPATIBLE WITH VOLLEY
			// return response()->json([
			// 	'message' => 'Unauthorized'], 401);
			
			// return response()->json([
			// 	'message' => 'Unauthorized'], 201);

			return response()->json([
				'message' => 'Unauthorized']);
		}

		$user = $request->user();
		$tokenResult = $user->createToken('Personal Access Token');
		$token = $tokenResult->token;
		if ($request->remember_me) {
			$token->expires_at = Carbon::now()->addWeeks(1);
		}
		$token->save();
		return response()->json([
			'access_token' => $tokenResult->accessToken,
			'token_type'   => 'Bearer',
			'expires_at'   => Carbon::parse(
				$tokenResult->token->expires_at)
			->toDateTimeString(),
		]);
	}

	public function logout(Request $request)
	{
		$request->user()->token()->revoke();
		return response()->json(['message' => 
			'Successfully logged out']);
	}

	public function user(Request $request)
	{
		return response()->json($request->user());
	}
}
