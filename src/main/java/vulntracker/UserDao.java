package vulntracker;

import java.sql.*;
import java.time.LocalDateTime;
import java.util.Optional;

public final class UserDao {
    public int create(String username, String fullName, String password, String role) throws SQLException {
        String sql = "INSERT INTO users(username,password_hash,full_name,role) VALUES(?,?,?,?)";
        try (Connection c = DBConnection.getInstance().getConnection(); PreparedStatement ps = c.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, username); ps.setString(2, PasswordUtil.hash(password)); ps.setString(3, fullName); ps.setString(4, role);
            ps.executeUpdate();
            try (ResultSet rs = ps.getGeneratedKeys()) { if (!rs.next()) throw new SQLException("No generated user id"); return rs.getInt(1); }
        }
    }

    public Optional<User> authenticate(String username, String password) throws SQLException {
        String sql = "SELECT user_id,username,password_hash,full_name,role,created_at FROM users WHERE username=?";
        try (Connection c = DBConnection.getInstance().getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next() || !PasswordUtil.verify(password, rs.getString("password_hash"))) return Optional.empty();
                return Optional.of(map(rs));
            }
        }
    }

    private User map(ResultSet rs) throws SQLException {
        int id=rs.getInt("user_id"); String u=rs.getString("username"); String n=rs.getString("full_name"); String h=rs.getString("password_hash");
        LocalDateTime created=rs.getTimestamp("created_at").toLocalDateTime();
        return switch(rs.getString("role")) { case "ADMIN" -> new Admin(id,u,n,h,created); case "ANALYST" -> new Analyst(id,u,n,h,created); case "ENGINEER" -> new Engineer(id,u,n,h,created); default -> throw new SQLException("Unknown role"); };
    }

    public int create(Connection connection, String username, String fullName,
                  String password, String role) throws SQLException {
    String sql = "INSERT INTO users(username,password_hash,full_name,role) VALUES(?,?,?,?)";

    try (PreparedStatement ps = connection.prepareStatement(
            sql, Statement.RETURN_GENERATED_KEYS)) {

        ps.setString(1, username);
        ps.setString(2, PasswordUtil.hash(password));
        ps.setString(3, fullName);
        ps.setString(4, role);

        ps.executeUpdate();

        try (ResultSet rs = ps.getGeneratedKeys()) {
            if (!rs.next()) {
                throw new SQLException("No generated user id");
            }
            return rs.getInt(1);
        }
    }
}
}
