package vulntracker;

import java.sql.*;
import java.time.LocalDate;

public final class TicketDao {
    public int create(int vulnId) throws SQLException {
        String sql="INSERT INTO ticket(vuln_id) VALUES(?)";
        try(Connection c=DBConnection.getInstance().getConnection(); PreparedStatement ps=c.prepareStatement(sql,Statement.RETURN_GENERATED_KEYS)){
            ps.setInt(1,vulnId); ps.executeUpdate(); try(ResultSet rs=ps.getGeneratedKeys()){if(!rs.next())throw new SQLException("No generated ticket id");return rs.getInt(1);}
        }
    }
    public void assign(int ticketId,int engineerId) throws SQLException {
        String sql="UPDATE ticket t JOIN users u ON u.user_id=? SET t.assigned_to=? WHERE t.ticket_id=? AND u.role='ENGINEER'";
        try(Connection c=DBConnection.getInstance().getConnection();PreparedStatement ps=c.prepareStatement(sql)){ps.setInt(1,engineerId);ps.setInt(2,engineerId);ps.setInt(3,ticketId);if(ps.executeUpdate()!=1)throw new SQLException("Ticket not found or user is not an engineer");}
    }
    public void updateStatus(int ticketId, TicketStatus status) throws SQLException {
        if(status==null)throw new IllegalArgumentException("Status is required");
        try(Connection c=DBConnection.getInstance().getConnection();PreparedStatement ps=c.prepareStatement("UPDATE ticket SET status=? WHERE ticket_id=?")){ps.setString(1,status.name());ps.setInt(2,ticketId);if(ps.executeUpdate()!=1)throw new SQLException("Ticket not found");}
    }
    public LocalDate findDueDate(int ticketId) throws SQLException {
        try(Connection c=DBConnection.getInstance().getConnection();PreparedStatement ps=c.prepareStatement("SELECT due_date FROM ticket WHERE ticket_id=?")){ps.setInt(1,ticketId);try(ResultSet rs=ps.executeQuery()){if(!rs.next())throw new SQLException("Ticket not found");return rs.getDate(1).toLocalDate();}}
    }
}
