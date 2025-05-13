//package com.CityRide.controller;
//
//import com.tickettrackmetro.entity.Booking;
//import com.tickettrackmetro.service.BookingService;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.web.bind.annotation.PostMapping;
//import org.springframework.web.bind.annotation.RequestBody;
//import org.springframework.web.bind.annotation.RestController;
//
//@RestController
//public class BookingController {
//
//	@Autowired
//	private BookingService bookingService;
//
//	@PostMapping("/getticket")
//	public Booking getTicket(@RequestBody Booking booking) {
//		return bookingService.getTicket(booking);
//	}
//
//	@PostMapping("/payment")
//	public String payment(Booking booking) {
//		return bookingService.payment(booking);
//	}
//}
