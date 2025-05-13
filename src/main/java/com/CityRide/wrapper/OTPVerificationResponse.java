package com.CityRide.wrapper;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
@Builder
public class OTPVerificationResponse {

    private String email;
    private String message;

}

