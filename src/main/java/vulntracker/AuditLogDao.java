package vulntracker;

import java.sql.*;

public final class AuditLogDao {
    public void record(Connection connection, int userId, String action, String details) throws SQLException {
        String sql = "INSERT INTO audit_log(user_id,action,details) VALUES(?,?,?)";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setInt(1, userId); ps.setString(2, action); ps.setString(3, details); ps.executeUpdate();
        }
    }
}
