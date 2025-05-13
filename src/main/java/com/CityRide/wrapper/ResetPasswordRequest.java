package com.CityRide.wrapper;

import lombok.*;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Validated
@EqualsAndHashCode
@ToString
public class ResetPasswordRequest {

    @Email(message = "Please provide a valid email address")
    @NotBlank(message = "Email cannot be blank")
    @NotNull(message = "Email cannot be null")
    private String email;

    @NotBlank(message = "New password cannot be blank")
    @NotNull(message = "New password cannot be null")
    @Size(min = 8, message = "New password must be at least 8 characters long")
    private String newPassword;

    @NotBlank(message = "Confirm password cannot be blank")
    @NotNull(message = "Confirm password cannot be null")
    @Size(min = 8, message = "Confirm password must be at least 8 characters long")
    private String confirmPassword;

    public @Email(message = "Please provide a valid email address") @NotBlank(message = "Email cannot be blank") @NotNull(message = "Email cannot be null") String getEmail() {
        return email;
    }

    public void setEmail(@Email(message = "Please provide a valid email address") @NotBlank(message = "Email cannot be blank") @NotNull(message = "Email cannot be null") String email) {
        this.email = email;
    }

    public @NotBlank(message = "New password cannot be blank") @NotNull(message = "New password cannot be null") @Size(min = 8, message = "New password must be at least 8 characters long") String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(@NotBlank(message = "New password cannot be blank") @NotNull(message = "New password cannot be null") @Size(min = 8, message = "New password must be at least 8 characters long") String newPassword) {
        this.newPassword = newPassword;
    }

    public @NotBlank(message = "Confirm password cannot be blank") @NotNull(message = "Confirm password cannot be null") @Size(min = 8, message = "Confirm password must be at least 8 characters long") String getConfirmPassword() {
        return confirmPassword;
    }

    public void setConfirmPassword(@NotBlank(message = "Confirm password cannot be blank") @NotNull(message = "Confirm password cannot be null") @Size(min = 8, message = "Confirm password must be at least 8 characters long") String confirmPassword) {
        this.confirmPassword = confirmPassword;
    }
}


