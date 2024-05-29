<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\Api\LoginUserRequest;
use App\Models\User;
use App\Permissions\V1\Abilities;
use App\Traits\ApiResponses;
use Illuminate\Http\JsonResponse;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    use ApiResponses;


    /**
     * Login
     * 
     * Authenticates the user and returns the user's API token.
     * 
     * @unauthenticated
     * @group Authentication
     * @response 200 {
    "data": {
        "token": "{YOUR_AUTH_KEY}"
    },
    "message": "Authenticated",
    "status": 200
}
     */
    public function login(LoginUserRequest $request) {
        $request->validated($request->all());

        if (!Auth::attempt($request->only('email', 'password'))) {
            return $this->error('Invalid credentials', 401);
        }

        $user = User::firstWhere('email', $request->email);

        return $this->ok(
            'Authenticated',
            [
                'token' => $user->createToken(
                    'API token for ' . $user->email,
                    Abilities::getAbilities($user),
                    now()->addMonth())->plainTextToken
            ]
            );
    }
    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required',
            'email' => 'required|email|unique:users',
            'password' => 'required|min:6',
        ]);
        $data = $request->all();
        $check =  User::create($data);
        return $this->ok('Register  successfully' , $check);
    }

    /**
     * Logout
     * 
     * Signs out the user and destroy's the API token.
     * 
     * @group Authentication
     * @response 200 {}
     */
    public function logout(Request $request) {
        $request->user()->currentAccessToken()->delete();

        return $this->ok('');
    }
}
