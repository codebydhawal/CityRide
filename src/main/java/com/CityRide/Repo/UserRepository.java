package com.CityRide.Repo;

import com.CityRide.entity.Role;
import com.CityRide.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

	Optional<User> findByEmail(String email);

	boolean existsByEmail(String email);

	Optional<User> findByRolesContaining(Role teamLeadRole);

	Optional<User> findByRolesName(String string);
}
