package vulntracker;

import java.sql.*;

public final class TicketService {
    private final AuditLogDao auditLogs = new AuditLogDao();

    public void assign(User admin, int ticketId, int engineerId) throws SQLException {
        requireRole(admin, "ADMIN");
        try (Connection c = DBConnection.getInstance().getConnection()) {
            c.setAutoCommit(false);
            try {
                String sql = "UPDATE ticket t JOIN users u ON u.user_id=? SET t.assigned_to=? WHERE t.ticket_id=? AND u.role='ENGINEER'";
                try (PreparedStatement ps=c.prepareStatement(sql)) {
                    ps.setInt(1, engineerId); ps.setInt(2, engineerId); ps.setInt(3, ticketId);
                    if (ps.executeUpdate() != 1) throw new SQLException("Ticket not found or target user is not an engineer");
                }
                auditLogs.record(c, admin.getUserId(), "ASSIGN_TICKET", "ticketId=" + ticketId + ", engineerId=" + engineerId);
                c.commit();
            } catch (SQLException | RuntimeException e) { c.rollback(); throw e; }
            finally { c.setAutoCommit(true); }
        }
    }

    public void updateStatus(User engineer, int ticketId, TicketStatus status) throws SQLException {
        requireRole(engineer, "ENGINEER");
        if (status == null) throw new IllegalArgumentException("Status is required");
        try (Connection c = DBConnection.getInstance().getConnection()) {
            String currentSql = "SELECT status FROM ticket WHERE ticket_id=? AND assigned_to=?";
            TicketStatus current;
            try (PreparedStatement ps = c.prepareStatement(currentSql)) {
                ps.setInt(1, ticketId); ps.setInt(2, engineer.getUserId());
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) throw new SecurityException("Ticket is not assigned to this engineer");
                    current = TicketStatus.valueOf(rs.getString(1));
                }
            }
            if (current == TicketStatus.CLOSED && status != TicketStatus.CLOSED) throw new IllegalStateException("Closed ticket cannot be reopened");
            if (current == TicketStatus.OPEN && status == TicketStatus.RESOLVED) throw new IllegalStateException("Ticket must be in progress before resolution");
            c.setAutoCommit(false);
            try {
                String sql="UPDATE ticket SET status=? WHERE ticket_id=? AND assigned_to=?";
                try (PreparedStatement ps=c.prepareStatement(sql)) {
                    ps.setString(1,status.name()); ps.setInt(2,ticketId); ps.setInt(3,engineer.getUserId());
                    if(ps.executeUpdate()!=1) throw new SecurityException("Ticket is not assigned to this engineer");
                }
                auditLogs.record(c, engineer.getUserId(), "UPDATE_TICKET_STATUS", "ticketId="+ticketId+", status="+status);
                c.commit();
            } catch (SQLException | RuntimeException e) { c.rollback(); throw e; }
            finally { c.setAutoCommit(true); }
        }
    }

    private void requireRole(User user, String role) { if (user == null || !role.equals(user.getRole())) throw new SecurityException("Insufficient role"); }
}
