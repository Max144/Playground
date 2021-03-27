<?php

use App\Http\Controllers\Auth\ApiAuthController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::group(['middleware' => ['cors', 'json.response']], function () {
    Route::prefix('auth')->group(function () {
        Route::post('/login', [ApiAuthController::class, 'login'])->name('login');
        Route::post('/register',[ApiAuthController::class, 'register'])->name('register');

        Route::group(['middleware' => ['auth:api']], function () {
            Route::post('/logout', [ApiAuthController::class, 'logout'])->name('logout');
            Route::get('/me', [ApiAuthController::class, 'me'])->name('me');
        });
    });
});