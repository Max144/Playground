<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use App\Http\Requests\Auth\RegisterRequest;
use Illuminate\Http\JsonResponse;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

class ApiAuthController extends Controller
{
    /**
     * Get a JWT token for newly registered user.
     *
     * @param RegisterRequest $request
     *
     * @return JsonResponse
     *
     * @OA\Post(
     *     path="/api/auth/register",
     *     operationId="auth.register",
     *     tags={"AuthController"},
     *     description="user register",
     *     @OA\Parameter(
     *          name="name",
     *          description="user name",
     *          required=true,
     *          in="query",
     *          @OA\Schema(
     *              type="string",
     *          )
     *      ),
     *     @OA\Parameter(
     *          name="email",
     *          description="Email",
     *          required=true,
     *          in="query",
     *          @OA\Schema(
     *              type="string",
     *          )
     *      ),
     *     @OA\Parameter(
     *          name="password",
     *          description="Password",
     *          required=true,
     *          in="query",
     *          @OA\Schema(
     *              type="string",
     *          )
     *      ),
     *     @OA\Parameter(
     *          name="password_confirmation",
     *          description="Password confirmation - must be the same as password",
     *          required=true,
     *          in="query",
     *          @OA\Schema(
     *              type="string",
     *          )
     *      ),
     *     @OA\Response(
     *          response=200,
     *          description="successful login",
     *          @OA\JsonContent(),
     *       ),
     *     @OA\Response(
     *          response=401,
     *          description="wrong data provided",
     *          @OA\JsonContent(),
     *       ),
     * )
     */
    public function register(RegisterRequest $request): JsonResponse
    {
        $userData = $request->validated();
        $userData['password'] = Hash::make($userData['password']);
        $userData['remember_token'] = Str::random(10);

        $user = User::create($userData);
        $token = $user->createToken('Laravel Password Grant Client')->accessToken;

        return response()->json(['token' => $token]);
    }

    /**
     * Get a JWT token via given credentials.
     *
     * @param LoginRequest $request
     *
     * @return JsonResponse
     *
     * @OA\Post(
     *     path="/api/auth/login",
     *     operationId="auth.login",
     *     tags={"AuthController"},
     *     description="user login",
     *     @OA\Parameter(
     *          name="email",
     *          description="Email",
     *          required=true,
     *          in="query",
     *          @OA\Schema(
     *              type="string",
     *          )
     *      ),
     *     @OA\Parameter(
     *          name="password",
     *          description="Password",
     *          required=true,
     *          in="query",
     *          @OA\Schema(
     *              type="string",
     *          )
     *      ),
     *     @OA\Parameter(
     *          name="password_confirmation",
     *          description="Password confirmation - must be the same as password",
     *          required=true,
     *          in="query",
     *          @OA\Schema(
     *              type="string",
     *          )
     *      ),
     *     @OA\Response(
     *          response=200,
     *          description="successful login",
     *          @OA\JsonContent(),
     *       ),
     *     @OA\Response(
     *          response=422,
     *          description="wrong data provided",
     *          @OA\JsonContent(),
     *       ),
     * )
     */
    public function login(LoginRequest $request): JsonResponse
    {
        $user = User::where('email', $request->email)->first();
        if ($user) {
            if (Hash::check($request->password, $user->password)) {
                $token = $user->createToken('Laravel Password Grant Client')->accessToken;
                return response()->json(['token' => $token]);
            } else {
                return response()->json(['message' => "Password mismatch"], 422);
            }
        } else {
            return response()->json(['message' => "User does not exist"], 422);
        }
    }

    /**
     * Get the authenticated User
     *
     * @return JsonResponse
     * @OA\Get(
     *     path="/api/auth/me",
     *     operationId="auth.me",
     *     security={{"bearer":{}}},
     *     tags={"AuthController"},
     *     description="user info",
     *     @OA\Response(
     *          response=200,
     *          description="current user info returned",
     *          @OA\JsonContent(),
     *       ),
     *     @OA\Response(
     *          response=401,
     *          description="unauthorized",
     *          @OA\JsonContent(),
     *       ),
     *     security={ {"bearer": {}} },
     * )
     */
    public function me () {
        return response()->json(auth()->user());
    }

    /**
     * Revoke user's token
     *
     * @return JsonResponse
     * @OA\Post (
     *     path="/api/auth/logout",
     *     operationId="auth.logout",
     *     tags={"AuthController"},
     *     description="user token revoke access",
     *     @OA\Response(
     *          response=200,
     *          description="current user token revoke access",
     *          @OA\JsonContent(),
     *       ),
     *     @OA\Response(
     *          response=401,
     *          description="unauthorized",
     *          @OA\JsonContent(),
     *       ),
     *     security={ {"bearer": {}} },
     * )
     */
    public function logout () {
        $token = auth()->user()->token();
        $token->revoke();

        return response()->json(['message' => "You have been successfully logged out!"]);
    }
}
