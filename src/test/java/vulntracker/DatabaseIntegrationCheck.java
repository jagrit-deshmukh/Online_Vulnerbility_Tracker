package vulntracker;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.LocalDate;
import java.util.Optional;
import java.util.UUID;

/**
 * End-to-end JDBC smoke test. Run only against a dedicated development database.
 * It creates temporary users/data and removes everything it created.
 */
public final class DatabaseIntegrationCheck {
    private DatabaseIntegrationCheck() {}

    public static void main(String[] args) throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String adminUsername = "it_admin_" + suffix;
        String analystUsername = "it_analyst_" + suffix;
        String engineerUsername = "it_engineer_" + suffix;
        String password = "IntegrationPass!123";
        UserDao users = new UserDao();
        AuthService auth = new AuthService();
        VulnerabilityService vulnerabilities = new VulnerabilityService();
        TicketService tickets = new TicketService();
        CommentDao comments = new CommentDao();

        int adminId = 0, analystId = 0, engineerId = 0, vulnId = 0, ticketId = 0;
        try {
            adminId = users.create(adminUsername, "Integration Admin", password, "ADMIN");
            analystId = users.create(analystUsername, "Integration Analyst", password, "ANALYST");
            engineerId = users.create(engineerUsername, "Integration Engineer", password, "ENGINEER");

            User admin = required(auth.login(adminUsername, password), "admin login");
            User analyst = required(auth.login(analystUsername, password), "analyst login");
            User engineer = required(auth.login(engineerUsername, password), "engineer login");

            Vulnerability vulnerability = new Vulnerability(
                    0,
                    "Integration-test critical finding",
                    "Temporary vulnerability used by the JDBC integration test.",
                    Severity.CRITICAL,
                    "CVE-TEST-0001",
                    analyst.getUserId(),
                    null
            );

            ticketId = vulnerabilities.report(analyst, vulnerability);
            vulnId = findVulnerabilityId(ticketId);

            LocalDate dueDate = findDueDate(ticketId);
            assertEquals(LocalDate.now().plusDays(1), dueDate, "Critical SLA must be one day");

            tickets.assign(admin, ticketId, engineer.getUserId());
            assertEquals(engineer.getUserId(), findAssignedEngineer(ticketId), "Assignment failed");

            tickets.updateStatus(engineer, ticketId, TicketStatus.IN_PROGRESS);
            assertEquals("IN_PROGRESS", findStatus(ticketId), "Status update failed");

            comments.create(ticketId, engineer.getUserId(), "Integration test comment");
            assertCondition(countComments(ticketId) >= 1, "Comment was not persisted");

            tickets.updateStatus(engineer, ticketId, TicketStatus.RESOLVED);
            assertEquals("RESOLVED", findStatus(ticketId), "Resolution failed");

            assertCondition(countAuditEntries(analyst.getUserId()) >= 1, "Analyst audit entry missing");
            assertCondition(countAuditEntries(admin.getUserId()) >= 1, "Admin audit entry missing");
            assertCondition(countAuditEntries(engineer.getUserId()) >= 2, "Engineer audit entries missing");

            System.out.println("DATABASE INTEGRATION CHECK: PASS");
            System.out.println("  Authentication: PASS");
            System.out.println("  Report -> Ticket transaction: PASS");
            System.out.println("  Critical SLA: PASS");
            System.out.println("  Admin assignment: PASS");
            System.out.println("  Engineer status workflow: PASS");
            System.out.println("  Comment persistence: PASS");
            System.out.println("  Audit trail: PASS");
        } finally {
            cleanup(ticketId, vulnId, adminId, analystId, engineerId);
        }
    }

    private static User required(Optional<User> user, String operation) {
        if (user.isEmpty()) throw new AssertionError(operation + " failed");
        return user.get();
    }

    private static int findVulnerabilityId(int ticketId) throws Exception {
        try (Connection c = DBConnection.getInstance().getConnection();
             PreparedStatement ps = c.prepareStatement("SELECT vuln_id FROM ticket WHERE ticket_id=?")) {
            ps.setInt(1, ticketId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) throw new AssertionError("Ticket not found");
                return rs.getInt(1);
            }
        }
    }

    private static LocalDate findDueDate(int ticketId) throws Exception {
        try (Connection c = DBConnection.getInstance().getConnection();
             PreparedStatement ps = c.prepareStatement("SELECT due_date FROM ticket WHERE ticket_id=?")) {
            ps.setInt(1, ticketId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next() || rs.getDate(1) == null) throw new AssertionError("Due date missing");
                return rs.getDate(1).toLocalDate();
            }
        }
    }

    private static int findAssignedEngineer(int ticketId) throws Exception {
        try (Connection c = DBConnection.getInstance().getConnection();
             PreparedStatement ps = c.prepareStatement("SELECT assigned_to FROM ticket WHERE ticket_id=?")) {
            ps.setInt(1, ticketId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) throw new AssertionError("Ticket not found");
                return rs.getInt(1);
            }
        }
    }

    private static String findStatus(int ticketId) throws Exception {
        try (Connection c = DBConnection.getInstance().getConnection();
             PreparedStatement ps = c.prepareStatement("SELECT status FROM ticket WHERE ticket_id=?")) {
            ps.setInt(1, ticketId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) throw new AssertionError("Ticket not found");
                return rs.getString(1);
            }
        }
    }

    private static int countComments(int ticketId) throws Exception {
        return count("SELECT COUNT(*) FROM comment WHERE ticket_id=?", ticketId);
    }

    private static int countAuditEntries(int userId) throws Exception {
        return count("SELECT COUNT(*) FROM audit_log WHERE user_id=?", userId);
    }

    private static int count(String sql, int id) throws Exception {
        try (Connection c = DBConnection.getInstance().getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setInt(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getInt(1);
            }
        }
    }

    private static void cleanup(int ticketId, int vulnId, int adminId, int analystId, int engineerId) throws Exception {
        try (Connection c = DBConnection.getInstance().getConnection()) {
            c.setAutoCommit(false);
            try {
                if (ticketId != 0) {
                    try (PreparedStatement ps = c.prepareStatement("DELETE FROM comment WHERE ticket_id=?")) { ps.setInt(1, ticketId); ps.executeUpdate(); }
                    try (PreparedStatement ps = c.prepareStatement("DELETE FROM audit_log WHERE details LIKE ?")) {
                        ps.setString(1, "%ticketId=" + ticketId + "%");
                        ps.executeUpdate();
                    }
                    try (PreparedStatement ps = c.prepareStatement("DELETE FROM ticket WHERE ticket_id=?")) { ps.setInt(1, ticketId); ps.executeUpdate(); }
                }
                if (vulnId != 0) {
                    try (PreparedStatement ps = c.prepareStatement("DELETE FROM vulnerability WHERE vuln_id=?")) { ps.setInt(1, vulnId); ps.executeUpdate(); }
                }
                if (adminId != 0 || analystId != 0 || engineerId != 0) {
                    try (PreparedStatement ps = c.prepareStatement("DELETE FROM audit_log WHERE user_id IN (?,?,?)")) {
                        ps.setInt(1, adminId); ps.setInt(2, analystId); ps.setInt(3, engineerId); ps.executeUpdate();
                    }
                    try (PreparedStatement ps = c.prepareStatement("DELETE FROM users WHERE user_id IN (?,?,?)")) {
                        ps.setInt(1, adminId); ps.setInt(2, analystId); ps.setInt(3, engineerId); ps.executeUpdate();
                    }
                }
                c.commit();
            } catch (Exception e) {
                c.rollback();
                throw e;
            } finally {
                c.setAutoCommit(true);
            }
        }
    }

    private static void assertCondition(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static void assertEquals(Object expected, Object actual, String message) {
        if (!expected.equals(actual)) throw new AssertionError(message + ": expected=" + expected + ", actual=" + actual);
    }
}
