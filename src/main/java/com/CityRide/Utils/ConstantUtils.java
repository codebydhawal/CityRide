package com.CityRide.Utils;

public class ConstantUtils {

    public static final String RESEND_OTP_MAIL_SUBJECT = "Your New OTP Code";
    public static final String ACCOUNT_REGISTRATION_EMAIL_SUBJECT = "Verification Code for Account Registration";
    public static final String RESET_PASSWORD_OTP_EMAIL_SUBJECT= "Your Password Reset OTP";

    public static final String RESEND_OTP_MAIL_MESSAGE = "To complete your verification process, New OTP is : ";
    public static final String RESET_PASSWORD_OTP_EMAIL_MESSAGE = "Dear %s, \n\n" +
            "Use this OTP for verification and for Password Reset: %s \n\n" +
            ", and This OTP is valid for 10 minutes.";
    public static final String OTP_MAIL_MESSAGE_FORMAT = "Your one-time password is ";
    public static final String RESET_PASSWORD_OTP_SENT = "OTP sent successfully to your email.";

    
    //password genrator related 
    public static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    public static final String DIGITS = "0123456789";
    public static final String SPECIAL_CHARS = "@#$%^&+=";
    public static final String ALL_CHARS = UPPERCASE + LOWERCASE + DIGITS + SPECIAL_CHARS;
}
