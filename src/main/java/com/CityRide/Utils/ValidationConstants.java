package com.CityRide.Utils;

import java.util.regex.Pattern;

public class ValidationConstants {

	// Email Constant
	public static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,6}$",
			Pattern.CASE_INSENSITIVE);
	public static final String INVALID_EMAIL = "Invalid email format, Email must start with a letter and should contain @ and end with '.com' or '.in";
	public static final String EMAIL_REQUIRED = "Email address is required.";
	public static final String EMAIL_VERIFICATION_REQUIRED = "Email Verification Needed: Please verify your email with the OTP sent to your registered email address";

	// Password Constant
	public static final Pattern PASSWORD_PATTERN = Pattern
			.compile("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,20}$", Pattern.CASE_INSENSITIVE);
	public static final String INVALID_PASSWORD = "Password must be 8-20 characters long and contain at least one digit, "
			+ "one lowercase letter, one uppercase letter, one special character, " + "and no whitespace";
	public static final String WRONG_PASSWORD = "Wrong password. Please make sure you've entered the correct password and try again.";
	public static final String PASSWORD_MISMATCH = "The passwords provided do not match. Please re-enter the new password and "
			+ "confirm password.";
	public static final String PASSWORD_SAME_AS_OLD = "New password cannot be the same as the existing password.";
	public static final String PASSWORD_VALIDATION_SUCCESS = "Passwords validated successfully.";
	public static final String PASSWORD_UPDATE_SUCCESS = "Password updated successfully.";
	public static final String DB_ERROR_UPDATE_PASSWORD = "Database error occurred while updating password.";
	public static final String PASSWORD_UPDATE_FAILURE = "Failed to update password. Please try again later.";

	// name Constant
	public static final Pattern NAME_PATTERN = Pattern.compile("^[A-Za-z][A-Za-z0-9]*$");
	public static final String INVALID_NAME = "Name must start with a letter and contain only letters and digits";

	// User Constant
	public static final String USER_NOT_FOUND = "User with email %s not found";

	public static final String USER_ALREADY_EXISTS = "User already exists. Please use a different email or proceed to login.";

	public static final String USER_SAVED_SUCCESSFULLY = "User saved successfully. Please verify your account using the OTP sent to your email.";
	public static final String USER_NOT_VERIFIED_MESSAGE = "User not verified for password reset.";

	// OTP Constant
	public static final String OTP_RESENT_SUCCESSFULLY = "OTP has been resent to the provided email.";
	public static final String OTP_NOT_FOUND = "OTP not found.";
	public static final String OTP_VERIFIED_SUCCESSFULLY = "OTP verified successfully.";
	public static final String OTP_VERIFIED_SUCCESSFULLY_FOR_PASSWORD_RESET = "OTP verified successfully for Reset Password.";
	public static final String INVALID_OR_EXPIRED_OTP = "Invalid or expired OTP.";

	// Error Constant
	public static final String DB_ERROR = "Database error occurred.";
	public static final String INTERNAL_SERVER_ERROR = "An unexpected error occurred. Please try again later.";
	public static final String BAD_REQUEST = "Bad request. OTP cannot be resent.";
	public static final String INVALID_USERNAME_PASSWORD = "Invalid username or password.";
	public static final String AGENT_SAVED_SUCCESSFULLY = "Agent Created successfully.";

}
