package com.CityRide.wrapper;

import com.CityRide.entity.Role;
import lombok.*;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class SignUpRequest implements Serializable {

	@NotNull(message = "Email cannot be blank")
	@NotBlank(message = "Email cannot be blank")
	private String email;

	@NotNull(message = "First Name cannot be blank")
	@NotBlank(message = "First Name cannot be blank")
	private String firstName;

	@NotNull(message = "Last Name cannot be blank")
	@NotBlank(message = "Last Name cannot be blank")
	private String lastName;

	@NotNull(message = "password Name cannot be blank")
	@NotBlank(message = "password Name cannot be blank")
	private String password;

	@NotNull(message = "roles cannot be blank")
	@NotBlank(message = "roles cannot be blank")
	private List<Role> roles;

	@NotNull(message = "Gender cannot be null")
	@NotBlank(message = "Gender cannot be blank")
	private String gender;

	public @NotNull(message = "Email cannot be blank") @NotBlank(message = "Email cannot be blank") String getEmail() {
		return email;
	}

	public void setEmail(@NotNull(message = "Email cannot be blank") @NotBlank(message = "Email cannot be blank") String email) {
		this.email = email;
	}

	public @NotNull(message = "First Name cannot be blank") @NotBlank(message = "First Name cannot be blank") String getFirstName() {
		return firstName;
	}

	public void setFirstName(@NotNull(message = "First Name cannot be blank") @NotBlank(message = "First Name cannot be blank") String firstName) {
		this.firstName = firstName;
	}

	public @NotNull(message = "Last Name cannot be blank") @NotBlank(message = "Last Name cannot be blank") String getLastName() {
		return lastName;
	}

	public void setLastName(@NotNull(message = "Last Name cannot be blank") @NotBlank(message = "Last Name cannot be blank") String lastName) {
		this.lastName = lastName;
	}

	public @NotNull(message = "password Name cannot be blank") @NotBlank(message = "password Name cannot be blank") String getPassword() {
		return password;
	}

	public void setPassword(@NotNull(message = "password Name cannot be blank") @NotBlank(message = "password Name cannot be blank") String password) {
		this.password = password;
	}

	public List<Role> getRoles() {
		return roles;
	}

	public void setRoles(@NotNull(message = "roles cannot be blank") @NotBlank(message = "roles cannot be blank") List<Role> roles) {
		this.roles = roles;
	}
}
