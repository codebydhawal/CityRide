package com.CityRide.controller;

import com.CityRide.Utils.ValidationConstants;
import com.CityRide.service.IAuthService;
import com.CityRide.wrapper.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/rest/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private IAuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<?> signUp(@RequestBody @Valid SignUpRequest signUpRequest) {
        try {
            ResponseEntity<SignUpResponse> response = authService.registerUser(signUpRequest);

            if (response.getStatusCode() == HttpStatus.BAD_REQUEST
                    || response.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                return response;
            }
            if (response.getStatusCode() == HttpStatus.CREATED) {
                SignUpResponse signUpResponse = response.getBody();
                return ResponseEntity.ok(signUpResponse);
            }
            return response;
        } catch (BadCredentialsException e) {
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.BAD_REQUEST, "Invalid username or password");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        } catch (Exception e) {
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    @PostMapping("/otpverify")
    public ResponseEntity<OTPVerificationResponse> verifyOTP(
            @RequestBody OTPVerificationRequest otpVerificationRequest) {
        try {
            logger.info("Entering OTPController :: verifyOTP method for email: {}", otpVerificationRequest.getEmail());

            if (otpVerificationRequest.getEmail() == null || otpVerificationRequest.getEmail().trim().isEmpty()) {
                String message = "Email is required.";
                logger.warn(message);
                return new ResponseEntity<>(OTPVerificationResponse.builder().message(message).build(),
                        HttpStatus.BAD_REQUEST);
            }

            if (otpVerificationRequest.getOtp() == null || otpVerificationRequest.getOtp().trim().isEmpty()
                    || otpVerificationRequest.getOtp().equalsIgnoreCase("null")) {
                String message = "OTP is required.";
                logger.warn(message);
                return new ResponseEntity<>(OTPVerificationResponse.builder().email(otpVerificationRequest.getEmail())
                        .message(message).build(), HttpStatus.BAD_REQUEST);
            }
            return authService.verifyOTP(otpVerificationRequest);

        } catch (Exception e) {
            String message = "Internal server error.";
            logger.error("Error in OTPController for email {}: {}", otpVerificationRequest.getEmail(), e.toString());
            return new ResponseEntity<>(
                    OTPVerificationResponse.builder().email(otpVerificationRequest.getEmail()).message(message).build(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @PostMapping("/login")
    public ResponseEntity<LogInResponse> login(@RequestBody @Validated LogInRequest logInRequest) {
        try {
            if (logInRequest != null) {
                return authService.login(logInRequest);
            } else {
                return ResponseEntity.badRequest().body(LogInResponse.builder().message(
                        "Invalid login request").build());
            }
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(LogInResponse.builder()
                            .message("Internal Server Error" +
                                    (logInRequest != null ? " for user: " + logInRequest.getEmail() : ""))
                            .build());

        }

    }

    @PostMapping("/resetpassword")
    public ResponseEntity<ResetPasswordResponse> resetPassword(
            @RequestBody @Validated ResetPasswordRequest resetPasswordRequest, HttpServletRequest request) {
        return authService.resetPassword(resetPasswordRequest, request);

    }


    @PostMapping("/sendpasswordresetotp")
    public ResponseEntity<ResetPasswordResponse> sendPasswordResetOTP(
            @RequestBody PasswordResetOTPRequest passwordResetOTPRequest) {
        return authService.sendPasswordResetOTP(passwordResetOTPRequest);

    }

    @PostMapping("/ressendotp")
    public ResponseEntity<ResendOTPResponse> resendOTP(@RequestParam String email) {
        try {
            if (email == null || email.isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(new ResendOTPResponse(email, ValidationConstants.EMAIL_REQUIRED));
            }
            return authService.resendOTP(email);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.badRequest()
                    .body(new ResendOTPResponse(email, ValidationConstants.INTERNAL_SERVER_ERROR));
        }

    }
}
