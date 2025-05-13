package com.CityRide.service;


import com.CityRide.entity.User;

import java.util.List;

public interface UserService {
    User getUserById(Long id);

    List<User> findAllUsers();

    User updateUser(Long id, User updatedUser);

    boolean deleteUser(Long id);

    User getUserByEmail(String email);

}
