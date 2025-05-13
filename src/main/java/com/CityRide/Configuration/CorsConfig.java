package com.CityRide.Configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsConfig implements WebMvcConfigurer {
	
	@Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOrigins("http://localhost:4200", "http://13.201.130.8")
                        .allowedHeaders("Content-Type", "Authorization", "ngrok-skip-browser-warning")
                        .allowedMethods("GET", "POST", "PUT", "DELETE")
                        .maxAge(3600);
            }
        };
    }
//	@Override
//	public void addCorsMappings(CorsRegistry registry) {
//		registry.addMapping("/**") // Applies to all endpoints
//				.allowedOrigins("http://localhost:4200") // Allow requests from Angular's origin
//				.allowedOrigins("http://13.201.130.8")
//				.allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS") // Allow specific HTTP methods
//				.allowedHeaders("Content-Type", "Authorization") // Headers allowed in the request
//				.allowCredentials(true) // Whether to allow sending credentials (cookies, tokens)
//				.maxAge(3600); // How long the preflight response is cached
//	}
}