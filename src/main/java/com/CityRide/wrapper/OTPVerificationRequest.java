package com.CityRide.wrapper;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class OTPVerificationRequest {

    @javax.validation.constraints.Email(message = "Please provide a valid email address")
    @javax.validation.constraints.NotBlank(message = "Email cannot be blank")
    @javax.validation.constraints.NotNull(message = "Email cannot be null")
    @JsonProperty("email")
    private String email;

   @JsonProperty("otp")
    private String otp;

    public @Email(message = "Please provide a valid email address") @NotBlank(message = "Email cannot be blank") @NotNull(message = "Email cannot be null") String getEmail() {
        return email;
    }

    public void setEmail(@Email(message = "Please provide a valid email address") @NotBlank(message = "Email cannot be blank") @NotNull(message = "Email cannot be null") String email) {
        this.email = email;
    }

    public String getOtp() {
        return otp;
    }

    public void setOtp(String otp) {
        this.otp = otp;
    }
}
