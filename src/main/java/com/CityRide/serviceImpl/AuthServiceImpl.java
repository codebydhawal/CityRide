package com.CityRide.serviceImpl;

import com.CityRide.Auth.JwtUtil;
import com.CityRide.Repo.OtpRepository;
import com.CityRide.Repo.RoleRepository;
import com.CityRide.Repo.UserRepository;
import com.CityRide.Utils.ConstantUtils;
import com.CityRide.Utils.ValidationConstants;
import com.CityRide.entity.OTP;
import com.CityRide.entity.Role;
import com.CityRide.entity.User;
import com.CityRide.service.IAuthService;
import com.CityRide.service.IOTPService;
import com.CityRide.wrapper.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.mail.internet.MimeMessage;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.xml.bind.ValidationException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class AuthServiceImpl implements IAuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder PasswordEncoder;

    @Autowired
    private IOTPService otpService;

    @Autowired
    private JavaMailSender javaMailSender;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private OtpRepository otpRepository;

    @Autowired
    private TemplateEngine templateEngine;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private RoleRepository roleRepository;

    @Override
    public ResponseEntity<SignUpResponse> registerUser(SignUpRequest signUpRequest) {
        logger.info("Entering AuthServiceImpl :: registerUser method...");

        String message = "";
        SignUpResponse response;
        try {
            ValidationResponse validationResult = validateSignUpRequest(signUpRequest);
            if (!validationResult.isValid()) {
                message = validationResult.getMessage();
                response = SignUpResponse.builder().message(message).build();
                logger.error(message);
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
            }

            String email = signUpRequest.getEmail();
            String firstName = signUpRequest.getFirstName();
            String lastName = signUpRequest.getLastName();
            List<Role> roles= signUpRequest.getRoles();
            String passsword = signUpRequest.getPassword();
            User user = new User();

            if (!isValidEmail(email)) {
                response = SignUpResponse.builder().message(ValidationConstants.INVALID_EMAIL).build();
                logger.error(ValidationConstants.INVALID_EMAIL);
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
            }
            if (!isValidFirstName(firstName)) {
                response = SignUpResponse.builder().message(ValidationConstants.INVALID_NAME).build();
                logger.error(ValidationConstants.INVALID_NAME);
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
            }
            if (!isValidLastName(lastName)) {
                response = SignUpResponse.builder().message(ValidationConstants.INVALID_NAME).build();
                logger.error(ValidationConstants.INVALID_NAME);
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
            }
            if (!isValidPassword(passsword)) {
                response = SignUpResponse.builder().message(ValidationConstants.INVALID_PASSWORD).build();
                logger.error(ValidationConstants.INVALID_PASSWORD);
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
            }

            Optional<User> existingUser = userRepository.findByEmail(email);
            if (existingUser.isPresent()) {
                response = SignUpResponse.builder().email(email).message(ValidationConstants.USER_ALREADY_EXISTS)
                        .build();
                logger.error(ValidationConstants.USER_ALREADY_EXISTS);
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
            }

            saveOtp(email);

            user.setEmail(email);
            user.setFirstName(firstName);
            user.setLastName(lastName);
            user.setGender(signUpRequest.getGender());
            user.setPassword(PasswordEncoder.encode(passsword));
            user.setIsVerified(false);
            user.setIsVerifiedForPasswordReset(false);

            List<Role> rolesFromDb = new ArrayList<>();
            for (Role role : signUpRequest.getRoles()) {
                Role roleFromDb = roleRepository.findByName(role.getName())
                        .orElseThrow(() -> new RuntimeException("Role not found: " + role.getName()));
                rolesFromDb.add(roleFromDb);
            }
            user.setRoles(rolesFromDb);
            userRepository.save(user);


            // Save the user entity
            user = userRepository.save(user);

            response = SignUpResponse.builder().email(email).message(ValidationConstants.USER_SAVED_SUCCESSFULLY).build();
            logger.info(ValidationConstants.USER_SAVED_SUCCESSFULLY);
            logger.info("AuthServiceImpl :: registerUser method end... Response: {}", response);
            return new ResponseEntity<SignUpResponse>(response, HttpStatus.CREATED);
        } catch (Exception e) {
            message = "Internal Server Error";
            response = SignUpResponse.builder().message(message).build();
            logger.error(message, e);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    public ResponseEntity<OTPVerificationResponse> verifyOTP(OTPVerificationRequest otpVerificationRequest) {
        logger.info("Entering AuthServiceImpl :: verifyOTP method");

        String message = "";
        OTPVerificationResponse failureResponse;
        OTPVerificationResponse successResponse;
        ValidationResponse validationResult;

        try {
            validationResult = validateOtpRequest(otpVerificationRequest);
            if (!validationResult.isValid()) {
                message = validationResult.getMessage();
                failureResponse = OTPVerificationResponse.builder().message(message).build();
                logger.error(message);
                return new ResponseEntity<>(failureResponse, HttpStatus.BAD_REQUEST);
            }

            String email = otpVerificationRequest.getEmail();
            if (!isValidEmail(email)) {
                failureResponse = OTPVerificationResponse.builder().message(ValidationConstants.INVALID_EMAIL).build();
                logger.error(ValidationConstants.INVALID_EMAIL);
                return new ResponseEntity<>(failureResponse, HttpStatus.BAD_REQUEST);
            }

            OTP existingOtp = otpRepository.findByEmail(email);

            if (existingOtp == null) {
                failureResponse = OTPVerificationResponse.builder().message(ValidationConstants.OTP_NOT_FOUND).email(email).build();
                logger.error(ValidationConstants.OTP_NOT_FOUND);
                return new ResponseEntity<>(failureResponse, HttpStatus.NOT_FOUND);

            }

            Integer storedOtp = existingOtp.getOneTimePassword();
            Integer requestOtp = Integer.valueOf(otpVerificationRequest.getOtp());

            LocalDateTime otpTimestamp = existingOtp.getOtpTimestamp();
            LocalDateTime now = LocalDateTime.now();

            // Validate OTP
            if (requestOtp.equals(storedOtp) && isOtpValid(otpTimestamp, now)) {
                Optional<User> userOptional = userRepository.findByEmail(email);
                if (userOptional.isPresent()) {
                    User user = userOptional.get();

                    if (user.getIsVerified()) {
                        user.setIsVerifiedForPasswordReset(true);
                        userRepository.save(user);
                        message = ValidationConstants.OTP_VERIFIED_SUCCESSFULLY_FOR_PASSWORD_RESET;
                        logger.info(message);
                    } else {
                        user.setIsVerified(true);
                        userRepository.save(user);
                        message = ValidationConstants.OTP_VERIFIED_SUCCESSFULLY;
                        logger.info(message);
                    }

                    successResponse = OTPVerificationResponse.builder().email(email).message(message).build();
                    return new ResponseEntity<>(successResponse, HttpStatus.OK);

                } else {
                    String errorMessage = String.format(ValidationConstants.USER_NOT_FOUND, email);
                    failureResponse = OTPVerificationResponse.builder().message(errorMessage).email(email).build();
                    logger.error(errorMessage);
                    return new ResponseEntity<>(failureResponse, HttpStatus.NOT_FOUND);

                }
            } else {
                logger.warn(ValidationConstants.INVALID_OR_EXPIRED_OTP);

                failureResponse = OTPVerificationResponse.builder().message(ValidationConstants.INVALID_OR_EXPIRED_OTP).email(email).build();
                logger.error(ValidationConstants.INVALID_OR_EXPIRED_OTP);
                return new ResponseEntity<>(failureResponse, HttpStatus.BAD_REQUEST);

            }
        } catch (Exception e) {
            String email = otpVerificationRequest.getEmail();
            logger.error("Error verifying OTP for email {}: {}", email, e.toString());
            failureResponse = OTPVerificationResponse.builder().message(ValidationConstants.INTERNAL_SERVER_ERROR).email(email).build();
            return new ResponseEntity<>(failureResponse, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    public ResponseEntity<LogInResponse> login(LogInRequest logInRequest) {
        logger.info("Entering AuthServiceImpl :: login method...");

        String message = "";
        LogInResponse response;
        try {
            // Validate login request
            ValidationResponse validationResult = validateLoginRequest(logInRequest);

            if (!validationResult.isValid()) {
                message = validationResult.getMessage();
                response = LogInResponse.builder().message(message).build();
                logger.error(message);
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
            }

            String userEmail = logInRequest.getEmail();
            String userPassword = logInRequest.getPassword();

            // Validate email format
            if (!isValidEmail(userEmail)) {
                response = LogInResponse.builder().message(ValidationConstants.INVALID_EMAIL).build();
                logger.error(ValidationConstants.INVALID_EMAIL);
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);

            }

            // Validate password format
            if (!isValidPassword(userPassword)) {
                response = LogInResponse.builder().message(ValidationConstants.INVALID_PASSWORD).build();
                logger.error(ValidationConstants.INVALID_PASSWORD);
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
            }

            // Check if user exists
            Optional<User> optionalUser = findUserByEmail(userEmail);
            if (optionalUser.isEmpty()) {
                response = LogInResponse.builder().message("User not found with email: " + userEmail).build();
                logger.error(ValidationConstants.USER_NOT_FOUND);
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
            }

            User existingUser = optionalUser.get();
            Boolean isVerified = existingUser.getIsVerified();

            // Check if password matches
            if (!isVerified && !PasswordEncoder.matches(userPassword, existingUser.getPassword())) {
                response = LogInResponse.builder().message(ValidationConstants.WRONG_PASSWORD).build();
                return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
            }

            // Create JWT token for authenticated user
            List<Role> roles = existingUser.getRoles();
            String token = jwtUtil.createToken(logInRequest, roles);

            response = LogInResponse.builder().message("Successfully logged in").email(userEmail).token(token).build();

            logger.info("User logged in successfully.");
            logger.info("AuthServiceImpl :: login method end...");
            return ResponseEntity.ok(response);

        } catch (Exception e) {

            response = LogInResponse.builder().message("An error occurred").build();
            logger.error("An error occurred", e);
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        }
    }

//	@Override
//	public ResponseEntity<ResetPasswordResponse> resetPassword(ResetPasswordRequest resetPasswordRequest, HttpServletRequest request) {
//		logger.info("Entering AuthServiceImpl :: resetPassword method...");
//
//		try {
//			// Log the reset password request
//			logger.debug("Reset password request: {}", resetPasswordRequest);
//
//			// Validate the reset password request
//			ValidationResponse validationResult = validateResetPasswordRequest(resetPasswordRequest);
//			if (!validationResult.isValid()) {
//				String message = validationResult.getMessage();
//				logger.error(message);
//				ResetPasswordResponse failureResponse = ResetPasswordResponse.builder().message(message).build();
//				return APIResponse.builder().error(true).body(failureResponse).message(message).build();
//			}
//
//			String email = resetPasswordRequest.getEmail();
//			String newPassword = resetPasswordRequest.getNewPassword();
//			String confirmPassword = resetPasswordRequest.getConfirmPassword();
//
//			// Check if the user exists
//			Optional<User> optionalUser = findUserByEmail(email);
//			if (optionalUser.isEmpty()) {
//				throw new EntityNotFoundException("User not found with email: " + email);
//			}
//
//			User existingUser = optionalUser.get();
//
//			if (existingUser.getRoles().stream().anyMatch(role -> role.getName().equalsIgnoreCase("AGENT"))) {
//				existingUser.setIsVerified(true);
//			}
//			
//			validateUser(existingUser);
//			
//			// Check if the user is verified for password reset
//			if (!existingUser.getIsVerifiedForPasswordReset()) {
//				return APIResponse.builder().error(true)
//						.body(new ResetPasswordResponse(email, ValidationConstants.USER_NOT_VERIFIED_MESSAGE))
//						.message(ValidationConstants.USER_NOT_VERIFIED_MESSAGE).build();
//			}
//
//			// Validate the email format
//			if (!isValidEmail(email)) {
//				String message = ValidationConstants.INVALID_EMAIL;
//				logger.error(message);
//				ResetPasswordResponse failureResponse = ResetPasswordResponse.builder().message(message).build();
//				return APIResponse.builder().error(true).body(failureResponse).message(message).build();
//			}
//
//			// Validate the new password format
//			if (!isValidPassword(newPassword)) {
//				String message = ValidationConstants.INVALID_PASSWORD;
//				logger.error(message);
//				ResetPasswordResponse failureResponse = ResetPasswordResponse.builder().message(message).build();
//				return APIResponse.builder().error(true).body(failureResponse).message(message).build();
//			}
//
//			// Validate the confirm password format
//			if (!isValidPassword(confirmPassword)) {
//				String message = ValidationConstants.INVALID_PASSWORD;
//				logger.error(message);
//				ResetPasswordResponse failureResponse = ResetPasswordResponse.builder().message(message).build();
//				return APIResponse.builder().error(true).body(failureResponse).message(message).build();
//			}
//
//			// Validate that the new password and confirm password match and are not the
//			// same as the existing password
//			validationResult = validatePasswords(existingUser.getPassword(), newPassword, confirmPassword);
//			if (!validationResult.isValid()) {
//				String message = validationResult.getMessage();
//				logger.error(message);
//				ResetPasswordResponse failureResponse = ResetPasswordResponse.builder().message(message).build();
//				return APIResponse.builder().error(true).body(failureResponse).message(message).build();
//			}
//
//			// Update the user's password
//			updateUserPassword(existingUser, newPassword);
//
//			// Check if the user is an agent and update the IsPasswordUpdated flag
//			if (existingUser.getRoles().stream().anyMatch(role -> role.getName().equalsIgnoreCase("AGENT"))) {
////				existingUser.setIsPasswordUpdated(true);
//				existingUser.setIsVerified(true);
//				userRepository.save(existingUser); // Save the updated user entity
//			}
//
//			String message = ValidationConstants.PASSWORD_UPDATE_SUCCESS;
//			ResetPasswordResponse response = ResetPasswordResponse.builder().message(message).email(email).build();
//			logger.debug("Reset password response: {}", response);
//			return APIResponse.builder().body(response).message(message).build();
//
//		} catch (EntityNotFoundException e) {
//			String message = "Entity not found: " + e.getMessage();
//			logger.error(message);
//			return APIResponse.builder().error(true).message(message).build();
//		} catch (ValidationException e) {
//			String message = "Validation error: " + e.getMessage();
//			logger.error(message);
//			return APIResponse.builder().error(true).message(message).build();
//		} catch (Exception e) {
//			String message = "Internal Server Error";
//			logger.error("An error occurred: {}", e.getMessage());
//			return APIResponse.builder().error(true).message(message).build();
//		} finally {
//			logger.info("AuthServiceImpl :: resetPassword method end...");
//		}
//	}

    @Override
    public ResponseEntity<ResetPasswordResponse> resetPassword(ResetPasswordRequest resetPasswordRequest, HttpServletRequest request) {
        logger.info("Entering AuthServiceImpl :: resetPassword method...");

        String message = "";
        HttpStatusCode httpStatusCode;
        ResetPasswordResponse failureResponse;
        ValidationResponse validationResult;
        ResetPasswordResponse updatePasswordResponse;

        try {
            // Log the reset password request
            logger.debug("Reset password request: {}", resetPasswordRequest);

            // Validate the reset password request
            validationResult = validateResetPasswordRequest(resetPasswordRequest);
            if (!validationResult.isValid()) {
                message = validationResult.getMessage();
                failureResponse = ResetPasswordResponse.builder().message(message).build();
                logger.error(message);
                return new ResponseEntity<>(failureResponse, HttpStatus.BAD_REQUEST);

            }

            String email = resetPasswordRequest.getEmail();
            String newPassword = resetPasswordRequest.getNewPassword();
            String confirmPassword = resetPasswordRequest.getConfirmPassword();

            // Check if the user exists
            Optional<User> optionalUser = findUserByEmail(email);
            if (optionalUser.isEmpty()) {
                throw new EntityNotFoundException("User not found with email: " + email);
            }

            User existingUser = optionalUser.get();

            validateUser(existingUser);

            // Check if the user is verified for password reset
            if (!existingUser.getIsVerifiedForPasswordReset()) {
                return ResponseEntity.badRequest().body(new ResetPasswordResponse(email, ValidationConstants.USER_NOT_VERIFIED_MESSAGE));
            }

            // Validate the email format
            if (!isValidEmail(email)) {
                failureResponse = ResetPasswordResponse.builder().message(ValidationConstants.INVALID_EMAIL).build();
                logger.error(ValidationConstants.INVALID_EMAIL);
                return new ResponseEntity<>(failureResponse, HttpStatus.BAD_REQUEST);
            }

            // Validate the new password format
            if (!isValidPassword(newPassword)) {
                failureResponse = ResetPasswordResponse.builder().message(ValidationConstants.INVALID_PASSWORD).build();
                logger.error(ValidationConstants.INVALID_PASSWORD);
                return new ResponseEntity<>(failureResponse, HttpStatus.BAD_REQUEST);
            }

            // Validate the confirm password format
            if (!isValidPassword(confirmPassword)) {
                failureResponse = ResetPasswordResponse.builder().message(ValidationConstants.INVALID_PASSWORD).build();
                logger.error(ValidationConstants.INVALID_PASSWORD);
                return new ResponseEntity<>(failureResponse, HttpStatus.BAD_REQUEST);
            }

            // Validate that the new password and confirm password match and are not the
            // same as the existing password
            validationResult = validatePasswords(existingUser.getPassword(), newPassword, confirmPassword);
            if (!validationResult.isValid()) {
                message = validationResult.getMessage();
                failureResponse = ResetPasswordResponse.builder().message(message).build();
                logger.error(message);
                return new ResponseEntity<>(failureResponse, HttpStatus.BAD_REQUEST);

            }

            // Update the user's password
            updatePasswordResponse = updateUserPassword(existingUser, newPassword);

//            // Check if the user is an agent and update the IsPasswordUpdated flag
//            if (existingUser.getRoles().stream().anyMatch(role -> role.getName().equalsIgnoreCase("AGENT"))) {
////				existingUser.setIsPasswordUpdated(true);
//                existingUser.setIsVerified(true);
//                userRepository.save(existingUser); // Save the updated user entity
//            }

            message = updatePasswordResponse.getMessage();
            ResetPasswordResponse response = ResetPasswordResponse.builder().message(message).email(email).build();
            logger.debug("Reset password response: {}", updatePasswordResponse);
            return new ResponseEntity<>(response, HttpStatus.OK);

        } catch (EntityNotFoundException e) {
            logger.error("Entity not found: {}", e.getMessage());
            return notFoundResponse("resetPasswordRequest.getEmail()", e.getMessage());
        } catch (ValidationException e) {
            logger.error("Validation error: {}", e.getMessage());
            return validationErrorResponse(resetPasswordRequest.getEmail(), e.getMessage());
        } catch (Exception e) {
            logger.error("An error occurred: {}", e.getMessage());
            return internalServerErrorResponse("resetPasswordRequest.getEmail()");
        } finally {
            logger.info("AuthServiceImpl :: resetPassword method end...");
        }

    }

    private ResetPasswordResponse updateUserPassword(User user, String newPassword) {
        try {
            logger.info("Inside the updateUserPassword method");

            String encodedPassword = PasswordEncoder.encode(newPassword);
            user.setPassword(encodedPassword);
            user.setIsVerifiedForPasswordReset(false);
            userRepository.save(user);
            logger.info("Password updated successfully for user: {}", user.getEmail());
            return ResetPasswordResponse.builder().message("Password updated successfully for user: " + user.getEmail()).email(user.getEmail()).build();

        } catch (DataAccessException e) {
            logger.error("Database error while updating password for user: {}", user.getEmail(), e);
            throw new RuntimeException(ValidationConstants.DB_ERROR_UPDATE_PASSWORD);
        } catch (Exception e) {
            logger.error("Unexpected error while updating password for user: {}", user.getEmail(), e);
            throw new RuntimeException(ValidationConstants.PASSWORD_UPDATE_FAILURE);
        }
    }


    @Override
    public OTP saveOtp(String email) {
        OTP otpEntity = otpService.createOtp(email);
        Integer otp = otpEntity.getOneTimePassword();
        String message = ConstantUtils.OTP_MAIL_MESSAGE_FORMAT + otp;
        sendEmail(message, ConstantUtils.ACCOUNT_REGISTRATION_EMAIL_SUBJECT, email);
        otpRepository.save(otpEntity);
        return otpEntity;
    }

    @Override
    public ResponseEntity<ResendOTPResponse> resendOTP(String email) {
        try {
            OTP otp = otpRepository.findByEmail(email);
            if (otp != null) {
                if (!otp.getOneTimePassword().equals("")) {
                    otp.setOneTimePassword(null);
                    Random random = new Random();
                    Integer newOtp = random.nextInt(100000, 999999);

                    String message = String.format(ConstantUtils.RESEND_OTP_MAIL_MESSAGE + newOtp);
                    sendEmail(message, ConstantUtils.RESEND_OTP_MAIL_SUBJECT, email);
                    otp.setOneTimePassword(newOtp);
                    otp.setOtpTimestamp(LocalDateTime.now());
                    otpRepository.save(otp);
                    return ResponseEntity.ok().body(new ResendOTPResponse(email, ValidationConstants.OTP_RESENT_SUCCESSFULLY));
                } else {
                    return ResponseEntity.ok().body(new ResendOTPResponse(email, ValidationConstants.BAD_REQUEST));
                }
            } else {
                return ResponseEntity.badRequest().body(new ResendOTPResponse(email, ValidationConstants.OTP_NOT_FOUND));
            }
        } catch (Exception e) {
            logger.error("Error resending OTP for email {}: {}", email, e.toString());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ResendOTPResponse(email, ValidationConstants.INTERNAL_SERVER_ERROR));

        }
    }

    @Override
    public ResponseEntity<ResetPasswordResponse> sendPasswordResetOTP(PasswordResetOTPRequest passwordResetOTPRequest) {
        ResetPasswordResponse failureResponse;
        ResetPasswordResponse successResponse;
        try {
            // Check if email is valid
            if (passwordResetOTPRequest.getEmail() == null || passwordResetOTPRequest.getEmail().isEmpty() || passwordResetOTPRequest.getEmail().equals("null")) {
                failureResponse = ResetPasswordResponse.builder().message(ValidationConstants.EMAIL_REQUIRED).build();
                logger.error(ValidationConstants.EMAIL_REQUIRED);
                return new ResponseEntity<>(failureResponse, HttpStatus.BAD_REQUEST);

            }

            String email = passwordResetOTPRequest.getEmail();

            // Validate email format
            if (!isValidEmail(email)) {
                failureResponse = ResetPasswordResponse.builder().message(ValidationConstants.INVALID_EMAIL).build();
                logger.error(ValidationConstants.INVALID_EMAIL);
                return new ResponseEntity<>(failureResponse, HttpStatus.BAD_REQUEST);

            }

            Optional<User> userOptional = userRepository.findByEmail(email);

            // Check if user exists
            if (userOptional.isEmpty()) {
                String errorMessage = String.format(ValidationConstants.USER_NOT_FOUND, email);
                failureResponse = ResetPasswordResponse.builder().message(errorMessage).build();
                logger.error(errorMessage);
                return new ResponseEntity<>(failureResponse, HttpStatus.BAD_REQUEST);
            }

            User user = userOptional.get();
            OTP otp = otpRepository.findByEmail(user.getEmail());

            // Check if user email is verified
            if (!user.getIsVerified()) {
                failureResponse = ResetPasswordResponse.builder().message(ValidationConstants.EMAIL_VERIFICATION_REQUIRED).build();
                logger.error(ValidationConstants.EMAIL_VERIFICATION_REQUIRED);
                return new ResponseEntity<>(failureResponse, HttpStatus.BAD_REQUEST);

            }

            // Generate and send OTP
            Random random = new Random();
            Integer newOtp = random.nextInt(100000, 999999);
            String subject = ConstantUtils.RESET_PASSWORD_OTP_EMAIL_SUBJECT;
            String message = String.format(ConstantUtils.RESET_PASSWORD_OTP_EMAIL_MESSAGE, user.getFirstName(), newOtp);

            sendEmail(message, subject, email);

            // Update OTP in database
            otp.setOneTimePassword(newOtp);
            otp.setOtpTimestamp(LocalDateTime.now());
            otpRepository.save(otp);

            successResponse = ResetPasswordResponse.builder().message(ConstantUtils.RESET_PASSWORD_OTP_SENT).email(email).build();
            logger.debug(ConstantUtils.RESET_PASSWORD_OTP_SENT);
            return new ResponseEntity<>(successResponse, HttpStatus.OK);
        } catch (DataAccessException e) {
            failureResponse = ResetPasswordResponse.builder().message(ValidationConstants.DB_ERROR).email(passwordResetOTPRequest.getEmail()).build();
            logger.error(ValidationConstants.DB_ERROR);
            return new ResponseEntity<>(failureResponse, HttpStatus.INTERNAL_SERVER_ERROR);

        } catch (Exception e) {
            failureResponse = ResetPasswordResponse.builder().message(ValidationConstants.INTERNAL_SERVER_ERROR).email(passwordResetOTPRequest.getEmail()).build();
            logger.error(ValidationConstants.INTERNAL_SERVER_ERROR);
            return new ResponseEntity<>(failureResponse, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    @Scheduled(fixedRate = 60000)
    public void otpUpdations() {
        LocalDateTime expirationTime = LocalDateTime.now().minusMinutes(5);
        List<OTP> expiredOtps = otpRepository.findByOtpTimestampBefore(expirationTime);
        for (OTP otp : expiredOtps) {
            otp.setOneTimePassword(null);
        }
        otpRepository.saveAll(expiredOtps);
    }

    private void sendEmail(String message, String subject, String email) {
        try {
            logger.debug("Inside the sendEmail method...");
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage, true);

            Context context = new Context();
            context.setVariable("content", message);
            String processedString = templateEngine.process("EmailTemplateForOTP", context);

            mimeMessageHelper.setTo(email);
            mimeMessageHelper.setSubject(subject);
            mimeMessageHelper.setText(processedString, true);

            javaMailSender.send(mimeMessage);
        } catch (Exception e) {
            logger.error("Failed to send email: {}", e.getMessage());
        }
    }

    private static boolean isValidEmail(String email) {
        return ValidationConstants.EMAIL_PATTERN.matcher(email).matches();
    }

    public static boolean isValidFirstName(String firstName) {
        return ValidationConstants.NAME_PATTERN.matcher(firstName).matches();
    }

    public static boolean isValidLastName(String lastName) {
        return ValidationConstants.NAME_PATTERN.matcher(lastName).matches();
    }

    private boolean isOtpValid(LocalDateTime otpTimestamp, LocalDateTime now) {
        return otpTimestamp.withSecond(0).withNano(0).isBefore(now) && otpTimestamp.withSecond(0).plusMinutes(5).isAfter(now);
    }

    private boolean isNullOrEmpty(String str) {
        return str == null || str.trim().isEmpty();
    }

    private ValidationResponse validateLoginRequest(LogInRequest loginRequest) {
        if (isNullOrEmpty(loginRequest.getEmail())) {
            return new ValidationResponse(false, "Email is required");
        }
        if (isNullOrEmpty(loginRequest.getPassword())) {
            return new ValidationResponse(false, "Password is required");
        }
        return new ValidationResponse(true, "Valid login request");
    }

    private ValidationResponse validateOtpRequest(OTPVerificationRequest otpVerificationRequest) {
        if (isNullOrEmpty(otpVerificationRequest.getOtp())) {
            return new ValidationResponse(false, "OTP is required");
        }
        if (isNullOrEmpty(otpVerificationRequest.getEmail())) {
            return new ValidationResponse(false, "Email is required");
        }
        return new ValidationResponse(true, "Valid OTP verification request");
    }

    private ValidationResponse validateResetPasswordRequest(ResetPasswordRequest resetPasswordRequest) {
        logger.debug("Inside the validateResetPasswordRequest method...");

        if (isNullOrEmpty(resetPasswordRequest.getEmail())) {
            return new ValidationResponse(false, "Email is required");
        }
        if (isNullOrEmpty(resetPasswordRequest.getNewPassword())) {
            return new ValidationResponse(false, "New Password is required");
        }
        if (isNullOrEmpty(resetPasswordRequest.getConfirmPassword())) {
            return new ValidationResponse(false, "Confirm Password is required");
        }
        return new ValidationResponse(true, "Valid reset password request");
    }

    private ValidationResponse validatePasswords(String existingPassword, String newPassword, String confirmPassword) {
        logger.debug("Inside the validatePasswords method...");

        if (PasswordEncoder.matches(newPassword, existingPassword)) {
            return new ValidationResponse(false, ValidationConstants.PASSWORD_SAME_AS_OLD);
        }
        if (!newPassword.equals(confirmPassword)) {
            return new ValidationResponse(false, ValidationConstants.PASSWORD_MISMATCH);
        }
        return new ValidationResponse(true, ValidationConstants.PASSWORD_VALIDATION_SUCCESS);
    }

    private boolean isValidPassword(String password) {
        return password != null && password.matches(ValidationConstants.PASSWORD_PATTERN.pattern());
    }

    private Optional<User> findUserByEmail(String userEmail) {
        return userRepository.findByEmail(userEmail);
    }


    private void validateUser(User user) throws ValidationException {
        if (user.getIsVerified() == null || !user.getIsVerified()) {
            throw new ValidationException("User must be verified");
        }
    }

//    private void validateAgent(Agent agent) throws ValidationException {
//        if (agent.getIsVerified() == null || !agent.getIsVerified()) {
//            throw new ValidationException("Agent must be verified");
//        }
//    }

//	private ResponseEntity<ResetPasswordResponse> updateUserPassword(User user, String newPassword) {
//	    try {
//	        logger.info("Inside the updateUserPassword method");
//
//	      List<Role>roles=  user.getRoles();
//	      for()
//	        // Check if the user role is "agent"
//	        if (!user.) {
//	            // Only encode password and reset verification for non-agent roles
//	            String encodedPassword = PasswordEncoder.encode(newPassword);
//	            user.setPassword(encodedPassword);
//	            user.setIsVerifiedForPasswordReset(false);
//	        } else {
//	            // For agents, update password without resetting verification
//	            String encodedPassword = PasswordEncoder.encode(newPassword);
//	            user.setPassword(encodedPassword);
//	        }
//
//	        user.setIsPasswordUpdated(true);
//	        userRepository.save(user);
//
//	        logger.info("Password updated successfully for user: {}", user.getEmail());
//	        return ResponseEntity.ok(new ResetPasswordResponse(user.getEmail(), ValidationConstants.PASSWORD_UPDATE_SUCCESS));
//	    } catch (DataAccessException e) {
//	        logger.error("Database error while updating password for user: {}", user.getEmail(), e);
//	        return buildErrorResponse(user.getEmail(), ValidationConstants.DB_ERROR_UPDATE_PASSWORD);
//	    } catch (Exception e) {
//	        logger.error("Unexpected error while updating password for user: {}", user.getEmail(), e);
//	        return buildErrorResponse(user.getEmail(), ValidationConstants.PASSWORD_UPDATE_FAILURE);
//	    }
//	}
//

//	private ResponseEntity<ResetPasswordResponse> updateAgentPassword(Agent agent, String newPassword) {
//		try {
//			logger.info("Inside the updateAgentPassword method");
//			String encodedPassword = PasswordEncoder.encode(newPassword);
//			agent.setPassword(encodedPassword);
//			agent.setIsVerifiedForPasswordReset(false);
//			agentRepository.save(agent);
//			logger.info("Password updated successfully for agent: {}", agent.getEmail());
//			return ResponseEntity
//					.ok(new ResetPasswordResponse(agent.getEmail(), ValidationConstants.PASSWORD_UPDATE_SUCCESS));
//		} catch (DataAccessException e) {
//			logger.error("Database error while updating password for agent: {}", agent.getEmail(), e);
//			return buildErrorResponse(agent.getEmail(), ValidationConstants.DB_ERROR_UPDATE_PASSWORD);
//		} catch (Exception e) {
//			logger.error("Unexpected error while updating password for agent: {}", agent.getEmail(), e);
//			return buildErrorResponse(agent.getEmail(), ValidationConstants.PASSWORD_UPDATE_FAILURE);
//		}
//	}

    private ResponseEntity<ResetPasswordResponse> buildErrorResponse(String email, String message) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ResetPasswordResponse(email, message));
    }

    private ResponseEntity<ResetPasswordResponse> notFoundResponse(String email, String message) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ResetPasswordResponse(email, message));
    }

    private ResponseEntity<ResetPasswordResponse> validationErrorResponse(String email, String message) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ResetPasswordResponse(email, message));
    }

    private ResponseEntity<ResetPasswordResponse> internalServerErrorResponse(String email) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ResetPasswordResponse(email, "An internal error occurred"));
    }
//	@Override
//	public User findUserByIdWithAgents(Long userId) {
//		Optional<User> userOpt = userRepository.findById(userId);
//		return userOpt.orElse(null);
//	}

    @Override
    public User getUserById(Long id) {
        try {
            Optional<User> userOptional = userRepository.findById(id);
            return userOptional.orElseThrow(() -> new IllegalArgumentException("User not found for ID: " + id));
        } catch (Exception e) {
            throw new RuntimeException("An error occurred while retrieving the user.", e);
        }
    }

    @Override
    public List<User> findAllUsers() {
        List<User> users = userRepository.findAll();
        if (users.isEmpty()) {
            throw new IllegalStateException("No users found.");
        }
        return users;
    }

    //
//    @Override
//    public ResponseEntity<List<User>> findAllUsers() {
//        try {
//            List<User> users = userRepository.findAll();
//            if (users.isEmpty()) {
//                return ResponseEntity.noContent().build();
//            }
//            return ResponseEntity.ok(users);
//        } catch (Exception e) {
//            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
//                                 .body(null);
//        }
//    }
//
//    @Override
//    public ResponseEntity<List<User>> getAgentsByTeamLeadId(Long teamLeadId) {
//        try {
//            List<User> agents = userRepository.findAgentsByTeamLeadId(teamLeadId);
//            if (agents.isEmpty()) {
//                return ResponseEntity.noContent().build();
//            }
//            return ResponseEntity.ok(agents);
//        } catch (Exception e) {
//            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
//                                 .body(null);
//        }
//    }
//
//    @Override
//    public ResponseEntity<List<User>> findAllTeamLeads() {
//        try {
//            List<User> teamLeads = userRepository.findAll().stream()
//                    .filter(user -> user.getRoles().stream()
//                            .anyMatch(role -> role.getName().equalsIgnoreCase("TEAM_LEAD")))
//                    .collect(Collectors.toList());
//
//            if (teamLeads.isEmpty()) {
//                return ResponseEntity.notFound().build();
//            }
//            return ResponseEntity.ok(teamLeads);
//        } catch (Exception e) {
//            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
//                                 .body(null);
//        }
//    }


    private ResponseEntity<?> buildErrorResponse(String message) {
        logger.error(message);
        return ResponseEntity.badRequest().body(Collections.singletonMap("error", message));
    }

    private ResponseEntity<?> handleException(Exception e, String message) {
        logger.error(message, e);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Collections.singletonMap("error", message));
    }

    private ValidationResponse validateSignUpRequest(SignUpRequest signUpRequest) {
        if (isNullOrEmpty(signUpRequest.getEmail())) {
            return new ValidationResponse(false, "Email is required");
        }
        if (isNullOrEmpty(signUpRequest.getFirstName())) {
            return new ValidationResponse(false, "First name is required");
        }
        if (isNullOrEmpty(signUpRequest.getLastName())) {
            return new ValidationResponse(false, "Last name is required");
        }
        if (isNullOrEmpty(signUpRequest.getPassword())) {
            return new ValidationResponse(false, "password is required");
        }
        return new ValidationResponse(true, "Valid sign-up request");

    }
}
