package vulntracker;

import java.sql.*;

public final class CommentDao {
    public int create(int ticketId, int userId, String text) throws SQLException {
        String sql = "INSERT INTO comment(ticket_id,user_id,text) VALUES(?,?,?)";
        try (Connection c = DBConnection.getInstance().getConnection(); PreparedStatement ps = c.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            ps.setInt(1, ticketId); ps.setInt(2, userId); ps.setString(3, text);
            ps.executeUpdate();
            try (ResultSet rs = ps.getGeneratedKeys()) { if (!rs.next()) throw new SQLException("No generated comment id"); return rs.getInt(1); }
        }
    }
}
