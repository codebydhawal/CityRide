package com.CityRide.service;

import com.CityRide.entity.*;
import com.CityRide.wrapper.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;

import java.util.List;

public interface IAuthService {

    ResponseEntity<SignUpResponse> registerUser(SignUpRequest signUpRequest);

    ResponseEntity<OTPVerificationResponse> verifyOTP(OTPVerificationRequest otpVerificationRequest);

    ResponseEntity<LogInResponse> login(LogInRequest logInRequest);

    ResponseEntity<ResetPasswordResponse> resetPassword(ResetPasswordRequest resetPasswordRequest, HttpServletRequest request);

    OTP saveOtp(String email);

    ResponseEntity<ResendOTPResponse> resendOTP(String email);


    ResponseEntity<ResetPasswordResponse> sendPasswordResetOTP(PasswordResetOTPRequest passwordResetOTPRequest);

    User getUserById(Long id);

    List<User> findAllUsers();


}
