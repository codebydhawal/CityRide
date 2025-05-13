package com.CityRide.Repo;

import com.CityRide.entity.OTP;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface OtpRepository extends JpaRepository<OTP, Long> {
	OTP findByEmail(String email);

	List<OTP> findByOtpTimestampBefore(LocalDateTime timestamp);
}
