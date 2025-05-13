package com.CityRide.service;

import com.CityRide.entity.Station;

import java.util.List;

public interface StationService {

    Station addStation(Station station);

    Station getStationById(Long id);

    List<Station> getAllStations();

    Station updateStation(Long id, Station station);

    void deleteStation(Long id);
}
