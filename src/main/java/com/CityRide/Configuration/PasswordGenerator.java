package com.CityRide.Configuration;//package com.tickettrackmetro.Configuration;
//
//
//import com.tickettrackmetro.Utils.ConstantUtils;
//
//import java.security.SecureRandom;
//import java.util.Collections;
//import java.util.List;
//import java.util.Random;
//import java.util.regex.Pattern;
//import java.util.stream.Collectors;
//
//public class PasswordGenerator {
//
//    private static final Random RANDOM = new SecureRandom();
//
//    // Password pattern
//    public static final Pattern PASSWORD_PATTERN = Pattern.compile(
//            "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,20}$", Pattern.CASE_INSENSITIVE);
//
//    public static String generateRandomPassword() {
//        int length = 8; // Fixed length of 8 characters
//
//        StringBuilder password = new StringBuilder(length);
//
//        password.append(getRandomChar(ConstantUtils.UPPERCASE));
//        password.append(getRandomChar(ConstantUtils.LOWERCASE));
//        password.append(getRandomChar(ConstantUtils.DIGITS));
//        password.append(getRandomChar(ConstantUtils.SPECIAL_CHARS));
//
//        for (int i = 4; i < length; i++) {
//            password.append(getRandomChar(ConstantUtils.ALL_CHARS));
//        }
//
//        return shuffleString(password.toString());
//    }
//
//    private static char getRandomChar(String source) {
//        return source.charAt(RANDOM.nextInt(source.length()));
//    }
//
//    private static String shuffleString(String string) {
//        List<Character> characters = string.chars().mapToObj(c -> (char) c).collect(Collectors.toList());
//        Collections.shuffle(characters, RANDOM);
//        StringBuilder shuffledString = new StringBuilder();
//        characters.forEach(shuffledString::append);
//        return shuffledString.toString();
//    }
//}
