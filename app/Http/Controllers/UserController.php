<?php

namespace App\Http\Controllers;

use Auth;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class UserController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(),[
            "name" => 'required|string|min:2|max:100',
            "email" => 'required|string|email|max:100|unique:users',
            "password" => "required|string|min:6|confirmed",
        ]);

        if ($validator->fails()){
            return response()->json($validator->errors(),400);
        }

        $user = User::create([
            "name" => $request->name,
            "email" => $request->email,
            "password" => Hash::make($request->password),
        ]);

        return response()->json([
            "status" => true,
            "message" => "User registered successfully",
            "user" => $user,
        ]);
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(),[
            "email" => 'required|string|email',
            "password" => "required|string",
        ]);

        if ($validator->fails()){
            return response()->json($validator->errors(),400);
        }

        if(!$token = auth()->attempt($validator->validated())){
            return response()->json(['error' => 'Unauthorized']);
        }

        return response()->json([
            "status" => true,
            "message" => "User logged in successfully",
            "data" => $this->respondWithToken($token),
        ]);
    }

    private function respondWithToken($token){

        return response()->json([
            "access_token" => $token,
            "token_type" => 'bearer',
            "expires_in" => auth()->factory()->getTTL()*60
        ]);
    }

    public function profile(){

        if(!auth()->user()){
            return response()->json([
                "status" => false,
                "message" => "Unauthorized User",
            ]);
        }

        return response()->json([
            "status" => true,
            "user" => auth()->user(),
        ]);

    }

    public function refresh(){
        if(!auth()->user()){
            return response()->json([
                "status" => false,
                "message" => "Unauthorized User",
            ]);
        }

        return response()->json([
            "status" => true,
            "token" => $this->respondWithToken(auth()->refresh()),
        ]);
    }

    public function logout(){

        if(!auth()->user()){

            return response()->json([
                "status" => false,
                "message" => "Logged out Failed",
            ]);
        }

        auth()->logout();

        return response()->json([
            "status" => true,
            "message" => "User has successfully logged out",
        ]);
    }
}
