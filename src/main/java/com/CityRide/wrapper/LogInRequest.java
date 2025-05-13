package com.CityRide.wrapper;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;


@AllArgsConstructor
@NoArgsConstructor
@Builder
@EqualsAndHashCode
@ToString
public class LogInRequest {

    @Email(message = "Please provide a valid email address")
    @NotBlank(message = "Email cannot be blank")
    @NotNull(message = "Email cannot be null")
    @JsonProperty("email")
    private String email;

    @NotBlank(message = "Password cannot be blank")
    @NotNull(message = "Password cannot be null")
    @JsonProperty("password")
    private String password;

    public @Email(message = "Please provide a valid email address") @NotBlank(message = "Email cannot be blank") @NotNull(message = "Email cannot be null") String getEmail() {
        return email;
    }

    public void setEmail(@Email(message = "Please provide a valid email address") @NotBlank(message = "Email cannot be blank") @NotNull(message = "Email cannot be null") String email) {
        this.email = email;
    }

    public @NotBlank(message = "Password cannot be blank") @NotNull(message = "Password cannot be null") String getPassword() {
        return password;
    }

    public void setPassword(@NotBlank(message = "Password cannot be blank") @NotNull(message = "Password cannot be null") String password) {
        this.password = password;
    }
}

