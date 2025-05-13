package com.CityRide.Configuration;//package com.tickettrackmetro.Configuration;
//
//import com.clientRacker.Entity.Listing;
//import org.springframework.data.jpa.domain.Specification;
//
//public class ListingSpecification {
//
//    public static Specification<Listing> hasMinPrice(Double minPrice) {
//        return (root, query, criteriaBuilder) -> {
//            if (minPrice == null) {
//                return criteriaBuilder.conjunction();
//            }
//            return criteriaBuilder.greaterThanOrEqualTo(root.get("price"), minPrice);
//        };
//    }
//
//    public static Specification<Listing> hasMaxPrice(Double maxPrice) {
//        return (root, query, criteriaBuilder) -> {
//            if (maxPrice == null) {
//                return criteriaBuilder.conjunction();
//            }
//            return criteriaBuilder.lessThanOrEqualTo(root.get("price"), maxPrice);
//        };
//    }
//
//    public static Specification<Listing> hasCategory(String category) {
//        return (root, query, criteriaBuilder) -> {
//            if (category == null) {
//                return criteriaBuilder.conjunction();
//            }
//            return criteriaBuilder.equal(root.get("category"), category);
//        };
//    }
//
//    public static Specification<Listing> hasBasement(Boolean basement) {
//        return (root, query, criteriaBuilder) -> {
//            if (basement == null) {
//                return criteriaBuilder.conjunction();
//            }
//            return criteriaBuilder.equal(root.get("basement"), basement);
//        };
//    }
//
//    public static Specification<Listing> hasBedrooms(Integer bedrooms) {
//        return (root, query, criteriaBuilder) -> {
//            if (bedrooms == null) {
//                return criteriaBuilder.conjunction();
//            }
//            return criteriaBuilder.equal(root.get("bedrooms"), bedrooms);
//        };
//    }
//
//    public static Specification<Listing> hasBathrooms(Integer bathrooms) {
//        return (root, query, criteriaBuilder) -> {
//            if (bathrooms == null) {
//                return criteriaBuilder.conjunction();
//            }
//            return criteriaBuilder.equal(root.get("bathrooms"), bathrooms);
//        };
//    }
//
//    public static Specification<Listing> hasGarage(Boolean garage) {
//        return (root, query, criteriaBuilder) -> {
//            if (garage == null) {
//                return criteriaBuilder.conjunction();
//            }
//            return criteriaBuilder.equal(root.get("garage"), garage);
//        };
//    }
//}
