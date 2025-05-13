package com.CityRide.controller;

import com.CityRide.entity.Station;
import com.CityRide.service.StationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/station")
public class StationController {

    @Autowired
    private StationService stationService;

    @PostMapping("/add")
    public ResponseEntity<Station> addStation(@RequestBody Station station) {
        return ResponseEntity.ok(stationService.addStation(station));
    }

    @GetMapping("/get")
    public ResponseEntity<Station> getStationById(@RequestParam Long id) {
        return ResponseEntity.ok(stationService.getStationById(id));
    }

    @GetMapping("/getall")
    public ResponseEntity<List<Station>> getAllStations() {
        return ResponseEntity.ok(stationService.getAllStations());
    }

    @PutMapping("/update")
    public ResponseEntity<Station> updateStation(@RequestParam Long id, @RequestBody Station station) {
        return ResponseEntity.ok(stationService.updateStation(id, station));
    }

    @DeleteMapping("/delete")
    public ResponseEntity<String> deleteStation(@RequestParam Long id) {
        stationService.deleteStation(id);
        return ResponseEntity.ok("Station deleted successfully");
    }
}
