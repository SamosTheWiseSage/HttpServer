package org.example;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.sql.*;
import java.util.Base64;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;

public class TimeCapsuleServer {

    private static final int PORT = 8080;
    private static final String DB_URL = "jdbc:mysql://localhost:3306/time_capsule_db";
    private static final String DB_USER = "root";  // Replace with your actual username
    private static final String DB_PASSWORD = "Underfell5958"; // Replace with your actual password
    private static final String SECRET_KEY = "mySuperSecretKey123";// Secure this key in production


    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Server is running on port " + PORT);
            while (true) {
                Socket clientSocket = serverSocket.accept();
                new Thread(() -> handleClient(clientSocket)).start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void handleClient(Socket clientSocket) {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
             PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {

            String request = in.readLine();
            String[] parts = request.split(",");
            String endpoint = parts[0];

            switch (endpoint) {
                case "register":
                    String email = parts[1];
                    String password = parts[2];
                    String response = registerUser(email, password);
                    out.println(response);
                    break;
                case "login":
                    email = parts[1];
                    password = parts[2];
                    response = loginUser(email, password);
                    out.println(response);
                    break;
                case "create":
                    String message = parts[1];
                    String jwt = parts[2];
                    response = createCapsule(message, jwt);
                    out.println(response);
                    break;
                case "read":
                    jwt = parts[1];
                    response = readCapsules(jwt);
                    out.println(response);
                    break;
                default:
                    out.println("Invalid request");
                    break;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String registerUser(String email, String password) throws SQLException {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement stmt = conn.prepareStatement("INSERT INTO users (email, password) VALUES (?, ?)")) {
            String hashedPassword = hashPassword(password);
            stmt.setString(1, email);
            stmt.setString(2, hashedPassword);
            stmt.executeUpdate();
            return "User registered successfully.";
        } catch (SQLException e) {
            if (e.getErrorCode() == 1062) {
                return "User already exists";
            }
            throw e;
        }
    }

    private static String loginUser(String email, String password) throws SQLException {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement stmt = conn.prepareStatement("SELECT password FROM users WHERE email = ?")) {
            stmt.setString(1, email);
            ResultSet rs = stmt.executeQuery();
            if (rs.next() && rs.getString("password").equals(hashPassword(password))) {
                String jwt = createJWT(email);
                return jwt; // Return JWT on successful login
            }
            return "Invalid credentials.";
        }
    }

    private static String createJWT(String email) {
        try {
            return Jwts.builder()
                    .setSubject(email)
                    .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                    .compact();
        } catch (Exception e) {
            e.printStackTrace();
            return null; // Handle exception
        }
    }

    private static String createCapsule(String message, String jwt) throws SQLException {
        if (jwt == null || !isValidToken(jwt)) {
            return "Invalid token";
        }
        String encryptedMessage = encrypt(message);
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement stmt = conn.prepareStatement("INSERT INTO capsules (email, message) VALUES (?, ?)")) {
            String email = Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(jwt).getBody().getSubject();
            stmt.setString(1, email);
            stmt.setString(2, encryptedMessage);
            stmt.executeUpdate();
            return "Capsule created successfully.";
        }
    }

    private static String readCapsules(String jwt) throws SQLException {
        if (jwt == null || !isValidToken(jwt)) {
            return "Invalid token";
        }
        String email = Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(jwt).getBody().getSubject();
        StringBuilder response = new StringBuilder();
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement stmt = conn.prepareStatement("SELECT message FROM capsules WHERE email = ?")) {
            stmt.setString(1, email);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                response.append(decrypt(rs.getString("message"))).append("\n");
            }
            return response.length() > 0 ? response.toString() : "No capsules found.";
        }
    }

    private static boolean isValidToken(String jwt) {
        try {
            Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(jwt);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static String encrypt(String data) {
        return Base64.getEncoder().encodeToString(data.getBytes());
    }

    private static String decrypt(String encryptedData) {
        return new String(Base64.getDecoder().decode(encryptedData));
    }

    private static String hashPassword(String password) {
        return Base64.getEncoder().encodeToString(password.getBytes());
    }
}