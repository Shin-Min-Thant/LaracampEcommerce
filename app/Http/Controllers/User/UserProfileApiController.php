<?php

namespace App\Http\Controllers\User;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Support\Facades\Validator;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class UserProfileApiController extends Controller
{

    // User Profile Edit
    public function UserProfileEdit()
    {
        $user = auth()->user();
        return response()->json([
            'status' => 200,
            'user' => $user
        ], 200);
    }
// -------------------------------------------------------------------------
// User Profile Store

    public function UserProfileStore(Request $request){
        $user = Auth::user();

        $validator = Validator::make($request->all(), [
            'username' => 'required|string|max:255',
            'address' => 'required|string',
            'phone' => 'required|string',
            'photo' => 'image|mimes:jpeg,png,jpg,gif|max:2048',
        ]);

        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], 422);
        }

        $user->name = $request->username;
        $user->address = $request->address;
        $user->phone = $request->phone;
        if ($request->file('photo')) {
            $file = $request->file('photo');
            @unlink(public_path('uploads/admin_imgs' . $user->photo));
            $filename = uniqid() . $file->getClientOriginalName();
            $file->move(public_path('uploads/user_img/'), $filename);
            $user['photo'] = $filename;
        }

        $user->save();


        if ($user) {
            return response()->json([
                'status' => 'Profile Updated Successfully',
                'user' => $user
            ], 200);
        } else {
            return response()->json([
                'status' => 404,
                'user' => "No found user"
            ]);
        }
    }

    // -----------------------------------------------------------
    // For Change Password
    public function UserChangePassword()
    {
        $user = Auth::user();
        if ($user) {
            return response()->json([
                'status' => 'User Change Password Successfully',
                'user' => $user
            ], 200);
        } else {
            return response()->json([
                'status' => 404,
                'user' => 'No User Found'
            ], 404);
        }
    }
    // -----------------------------------------------------------------------
    // User Password Update
    public function UserUpdatePassword(Request $request)
    {
        $user = Auth::user();

        $request->validate([
            'old_password' => 'required',
            'new_password' => 'required|confirmed|min:8',
        ]);

        if (Hash::check($request->old_password, $user->password)) {
            $user->password = Hash::make($request->new_password);
            $user->save();
            return response()->json(['message' => 'Password changed successfully'], 200);
        }

        return response()->json(['error' => 'Old password is incorrect'], 400);
    }

    //--------------------------------------------------------------------------
    // user update email
    public function UserUpdateEmail(Request $request)
    {
        $user = Auth::user();

        $request->validate([
            'new_email' => 'required|email|string|unique:users,email'
        ]);

        $user->email = $request->new_email;
        $user->save();

        return response()->json([
            "message" => "Successfully Updated"
        ], 200);
    }


    // --------------------------------------------------------------------------

    // For Store register
    public function RegisterStore(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:' . User::class],
            'password' => ['required', 'confirmed'],
            'password_confirmation' => ['required']
        ]);

        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], 422);
        };

        $user = User::create([
            'name' => $request->input('name'),
            'email' => $request->input('email'),
            'password' => bcrypt($request->input('password'))
        ]);

        auth()->login($user);

        return response()->json(['message' => 'User Created Account Successfully'], 200);
    }
    // ---------------------------------------------------------------------

    // For Show user

    public function showUser()
    {
        $user = User::all();
        if ($user) {
            return response()->json([
                'message' => 'These are all users',
                'user' => $user
            ], 200);
        } else {
            return response()->json([
                'message' => 'Users are not found',
                'user' => ''
            ], 404);
        };
    }



    // --------------------------------------------------------------------
    // For User Login
    public function UserLogin(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => ['required', 'string', 'email', 'max:255'],
            'password' => ['required'],
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 422);
        };

        $credentials = $request->only('email', 'password');


        if (Auth::attempt($credentials)) {
            $user = Auth::user();

            return response()->json([
                'message' => 'Login Successfully',
                'user' => $user,
            ], 200);
        } else {
            return response()->json(['message' => 'Email and password do not match'], 401);
        };
    }


    // ---------------------------------------------------------
    // For user logout
    public function UserLogout(Request $request)
    {

        if (auth()->check()) {
            auth()->logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();
            return response()->json(['message' => 'Logout Successfully'], 204);
        } else {
            return response()->json(['message' => 'User Logout Fail'], 400);
        }
    }
}
