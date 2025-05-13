package com.CityRide.Repo;

import com.CityRide.entity.Station;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface StationRepository extends JpaRepository<Station, Long> {

	Station findStationIdByStationName(String sourceStation);
}
