package com.CityRide.serviceImpl;

import com.CityRide.Exception.ResourceNotFoundException;
import com.CityRide.Repo.StationRepository;
import com.CityRide.entity.Station;
import com.CityRide.service.StationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class StationServiceImpl implements StationService {

    @Autowired
    private StationRepository stationRepository;

    @Override
    public Station addStation(Station station) {
        return stationRepository.save(station);
    }

    @Override
    public Station getStationById(Long id) {
        return stationRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Station not found with ID: " + id));
    }

    @Override
    public List<Station> getAllStations() {
        List<Station> stations = stationRepository.findAll();
        if (stations.isEmpty()) {
            throw new ResourceNotFoundException("No stations found.");
        }
        return stations;
    }

    @Override
    public Station updateStation(Long id, Station updatedStation) {
        Station existing = getStationById(id); // will throw exception if not found

        existing.setStationName(updatedStation.getStationName());
        existing.setLocation(updatedStation.getLocation());
        existing.setOperatingHours(updatedStation.getOperatingHours());
        existing.setZone(updatedStation.getZone());
        existing.setActive(updatedStation.isActive());

        return stationRepository.save(existing);
    }

    @Override
    public void deleteStation(Long id) {
        Station station = getStationById(id);
        stationRepository.delete(station);
    }
}
