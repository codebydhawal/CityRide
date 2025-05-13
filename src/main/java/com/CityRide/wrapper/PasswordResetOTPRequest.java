package com.CityRide.wrapper;

import lombok.*;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@EqualsAndHashCode
@ToString
public class PasswordResetOTPRequest {

    @Email(message = "Please provide a valid email address")
    @NotBlank(message = "Email cannot be blank")
    @NotNull(message = "Email cannot be null")
    private String email;

    public @Email(message = "Please provide a valid email address") @NotBlank(message = "Email cannot be blank") @NotNull(message = "Email cannot be null") String getEmail() {
        return email;
    }

    public void setEmail(@Email(message = "Please provide a valid email address") @NotBlank(message = "Email cannot be blank") @NotNull(message = "Email cannot be null") String email) {
        this.email = email;
    }
}

