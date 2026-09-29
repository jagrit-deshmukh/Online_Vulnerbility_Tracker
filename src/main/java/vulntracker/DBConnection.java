package vulntracker;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public final class DBConnection {
    private static DBConnection instance;
    private final String url;
    private final String username;
    private final String password;

    private DBConnection() {
        this.url = requireEnv("VULNTRACKER_DB_URL", "jdbc:mysql://localhost:3306/vulntracker?useSSL=false&serverTimezone=UTC");
        this.username = requireEnv("VULNTRACKER_DB_USER", "root");
        this.password = System.getenv().getOrDefault("VULNTRACKER_DB_PASSWORD", "");
    }
    public static synchronized DBConnection getInstance() { if (instance == null) instance = new DBConnection(); return instance; }
    public Connection getConnection() throws SQLException { return DriverManager.getConnection(url, username, password); }
    private static String requireEnv(String name, String fallback) { String v = System.getenv(name); return v == null || v.isBlank() ? fallback : v; }
}
