package com.CityRide.service;


import com.CityRide.entity.OTP;

public interface IOTPService {
    OTP createOtp(String email);
}
