//package com.CityRide.controller;
//
//import com.tickettrackmetro.entity.Schedule;
//import com.tickettrackmetro.service.SchedularService;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.RequestParam;
//import org.springframework.web.bind.annotation.RestController;
//
//import java.util.List;
//
//@RestController
//public class ScheduleController {
//
//	@Autowired
//	SchedularService schedularService;
//
//	@GetMapping("/getschedule")
//	public List<Schedule> getlist() {
//		return schedularService.getlist();
//
//	}
//
//	@GetMapping("/getScheduleByTime")
//	public List<Schedule> getSchduleByTime(@RequestParam String trainTimeing) {
//		return schedularService.getSchedulebyTime(trainTimeing);
//	}
//}
