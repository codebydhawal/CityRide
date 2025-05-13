package com.CityRide.serviceImpl;

import com.CityRide.Repo.UserRepository;
import com.CityRide.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        // Check in User repository first
        Optional<User> user = userRepository.findByEmail(email);
        if (user.isPresent()) {
            User userDetail = user.get();
            return org.springframework.security.core.userdetails.User.builder()
                    .username(userDetail.getEmail())
                    .password(userDetail.getPassword())
                    .authorities("ROLE_USER") // Set appropriate authorities/roles
                    .build();
        } else {
            // If not found in both repositories, throw exception
            throw new UsernameNotFoundException("User not found with email: " + email);
        }
    }
}

