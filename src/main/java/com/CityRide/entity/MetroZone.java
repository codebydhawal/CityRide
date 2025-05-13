package com.CityRide.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.List;

@Entity
@Table(name = "metro_zones")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MetroZone {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long zoneId;

    @Column(nullable = false, unique = true)
    private String zoneName;

    private String description;

    private boolean isActive = true;

    @OneToMany(mappedBy = "zone")
    private List<Station> stations;
}
