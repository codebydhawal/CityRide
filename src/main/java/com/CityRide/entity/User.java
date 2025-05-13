package com.CityRide.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonProperty.Access;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "User")
public class User {

    @Id
    @Basic
    @Column(name = "User_Id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Basic
    @Email(message = "Email should be valid")
    @NotNull(message = "Email cannot be null")
    @NotBlank(message = "Email cannot be blank")
    @Column(name = "Email", unique = true)
    private String email;

    @Basic
    @JsonProperty(access = Access.WRITE_ONLY)
    @NotNull(message = "Password cannot be null")
    @NotBlank(message = "Password cannot be blank")
    @Column(name = "Password")
    private String password;

    @Basic
    @NotNull(message = "First name cannot be null")
    @NotBlank(message = "First name cannot be blank")
    @Column(name = "First_Name")
    private String firstName;

    @Basic
    @NotNull(message = "Last name cannot be null")
    @NotBlank(message = "Last name cannot be blank")
    @Column(name = "Last_Name")
    private String lastName;

    @Basic
    @NotNull(message = "Gender cannot be null")
    @NotBlank(message = "Gender cannot be blank")
    @Column(name = "Gender")
    private String gender;

    @Column(name = "Is_Verified")
    @NotBlank
    @NotNull
    private Boolean isVerified;

    @Column(name = "is_Verified_For_Reset_Password")
    @NotBlank
    @NotNull
    private Boolean isVerifiedForPasswordReset;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "user_role", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
    private List<Role> roles = new ArrayList<>();
}
