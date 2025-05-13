package com.CityRide.serviceImpl;

import com.CityRide.entity.OTP;
import com.CityRide.service.IOTPService;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Random;

@Service
public class OTPServiceImpl implements IOTPService {

    public String generateOtp() {
        Random random = new Random();
        return String.format("%06d", random.nextInt(100000,999999));
    }

    public OTP createOtp(String email) {
        Integer otp = Integer.parseInt(generateOtp());
        LocalDateTime now = LocalDateTime.now();
        OTP otpEntity = OTP.builder().email(email).oneTimePassword(otp).otpTimestamp(now).build();
        return otpEntity;
    }


}
