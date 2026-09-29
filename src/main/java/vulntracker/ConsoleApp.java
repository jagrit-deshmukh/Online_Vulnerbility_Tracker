package vulntracker;

import java.sql.*;
import java.time.LocalDate;
import java.util.Optional;
import java.util.Scanner;

/** Interactive console UI. Business rules remain in services/database. */
public final class ConsoleApp {
    private final Scanner scanner;
    private final AuthService authService = new AuthService();
    private final VulnerabilityService vulnerabilityService = new VulnerabilityService();
    private final TicketService ticketService = new TicketService();
    private final CommentDao commentDao = new CommentDao();
    private final UserDao userDao = new UserDao();

    public ConsoleApp(Scanner scanner) { this.scanner = scanner; }

    public void run() {
        System.out.println("\n=== Online Vulnerability / Ticket Tracker ===");
        while (true) {
            System.out.println("\n1. Login\n0. Exit");
            String choice = prompt("Choice: ");
            if ("0".equals(choice)) return;
            if ("1".equals(choice)) login(); else System.out.println("Invalid choice.");
        }
    }

    private void login() {
        String username = prompt("Username: ");
        String password = prompt("Password: ");
        try {
            Optional<User> user = authService.login(username, password);
            if (user.isEmpty()) { System.out.println("Invalid username or password."); return; }
            System.out.println("\nWelcome, " + user.get().getFullName() + "!");
            switch (user.get().getRole()) {
                case "ADMIN" -> adminMenu(user.get());
                case "ANALYST" -> analystMenu(user.get());
                case "ENGINEER" -> engineerMenu(user.get());
                default -> System.out.println("Unsupported role.");
            }
        } catch (SQLException e) { databaseError(e); }
    }

    private void adminMenu(User admin) {
        while (true) {
            System.out.println("\n--- ADMIN DASHBOARD ---\n1. List users\n2. Create user\n3. List tickets\n4. Assign ticket\n5. View audit log\n6. View ticket details\n0. Logout");
            switch (prompt("Choice: ")) {
                case "1" -> listUsers();
                case "2" -> createUser();
                case "3" -> listTickets(null);
                case "4" -> assignTicket(admin);
                case "5" -> listAuditLog();
                case "6" -> viewTicketDetails();
                case "0" -> { return; }
                default -> System.out.println("Invalid choice.");
            }
        }
    }

    private void analystMenu(User analyst) {
        while (true) {
            System.out.println("\n--- ANALYST DASHBOARD ---\n1. Report vulnerability\n2. View my vulnerabilities\n3. View my tickets\n4. View ticket details\n0. Logout");
            switch (prompt("Choice: ")) {
                case "1" -> reportVulnerability(analyst);
                case "2" -> listVulnerabilities(analyst.getUserId());
                case "3" -> listTickets("reported_by=" + analyst.getUserId());
                case "4" -> viewTicketDetails();
                case "0" -> { return; }
                default -> System.out.println("Invalid choice.");
            }
        }
    }

    private void engineerMenu(User engineer) {
        while (true) {
            System.out.println("\n--- ENGINEER DASHBOARD ---\n1. View assigned tickets\n2. View ticket details\n3. Update ticket status\n4. Add comment\n5. View overdue tickets\n0. Logout");
            switch (prompt("Choice: ")) {
                case "1" -> listTickets("assigned_to=" + engineer.getUserId());
                case "2" -> viewTicketDetails();
                case "3" -> updateStatus(engineer);
                case "4" -> addComment(engineer);
                case "5" -> listOverdue(engineer.getUserId());
                case "0" -> { return; }
                default -> System.out.println("Invalid choice.");
            }
        }
    }

    private void reportVulnerability(User analyst) {
        try {
            String title = required("Title: ");
            String description = required("Description: ");
            Severity severity = parseSeverity(required("Severity (CRITICAL/HIGH/MEDIUM/LOW): "));
            String cve = prompt("CVE ID (optional): ");
            Vulnerability v = new Vulnerability(0, title, description, severity, cve.isBlank() ? null : cve, analyst.getUserId(), null);
            int ticketId = vulnerabilityService.report(analyst, v);
            System.out.println("Vulnerability reported. Ticket ID: " + ticketId);
            System.out.println("SLA: " + severity.getSlaDays() + " day(s), due approximately " + LocalDate.now().plusDays(severity.getSlaDays()));
        } catch (SQLException | RuntimeException e) { System.out.println("Could not report vulnerability: " + e.getMessage()); }
    }

    private void assignTicket(User admin) {
        try {
            int ticketId = integer("Ticket ID: ");
            int engineerId = integer("Engineer user ID: ");
            ticketService.assign(admin, ticketId, engineerId);
            System.out.println("Ticket assigned successfully.");
        } catch (SQLException | RuntimeException e) { System.out.println("Assignment failed: " + e.getMessage()); }
    }

    private void updateStatus(User engineer) {
        try {
            int ticketId = integer("Ticket ID: ");
            TicketStatus status = TicketStatus.valueOf(required("Status (OPEN/IN_PROGRESS/RESOLVED/CLOSED): ").toUpperCase());
            ticketService.updateStatus(engineer, ticketId, status);
            System.out.println("Status updated.");
        } catch (SQLException | RuntimeException e) { System.out.println("Status update failed: " + e.getMessage()); }
    }

    private void addComment(User user) {
        try {
            int ticketId = integer("Ticket ID: ");
            String text = required("Comment: ");
            int id = commentDao.create(ticketId, user.getUserId(), text);
            System.out.println("Comment added. ID: " + id);
        } catch (SQLException | RuntimeException e) { System.out.println("Could not add comment: " + e.getMessage()); }
    }

    private void listUsers() {
        String sql = "SELECT user_id, username, full_name, role, created_at FROM users ORDER BY user_id";
        try (Connection c = DBConnection.getInstance().getConnection(); PreparedStatement ps = c.prepareStatement(sql); ResultSet rs = ps.executeQuery()) {
            System.out.printf("%-5s %-18s %-25s %-10s %-20s%n", "ID", "USERNAME", "NAME", "ROLE", "CREATED");
            while (rs.next()) System.out.printf("%-5d %-18s %-25s %-10s %-20s%n", rs.getInt(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getTimestamp(5));
        } catch (SQLException e) { databaseError(e); }
    }

    private void createUser() {
        try {
            String username = required("Username: ");
            String name = required("Full name: ");
            String password = required("Password (min 8 chars): ");
            String role = required("Role (ADMIN/ANALYST/ENGINEER): ").toUpperCase();
            if (!role.equals("ADMIN") && !role.equals("ANALYST") && !role.equals("ENGINEER")) throw new IllegalArgumentException("Invalid role");
            int id = userDao.create(username, name, password, role);
            System.out.println("User created. ID: " + id);
        } catch (SQLException | RuntimeException e) { System.out.println("Could not create user: " + e.getMessage()); }
    }

    private void listVulnerabilities(int reporterId) {
        String sql = "SELECT vuln_id,title,severity,cve_id,reported_at FROM vulnerability WHERE reported_by=? ORDER BY vuln_id DESC";
        try (Connection c = DBConnection.getInstance().getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setInt(1, reporterId);
            try (ResultSet rs = ps.executeQuery()) {
                System.out.printf("%-5s %-35s %-10s %-18s %-20s%n", "ID", "TITLE", "SEVERITY", "CVE", "REPORTED");
                while (rs.next()) System.out.printf("%-5d %-35s %-10s %-18s %-20s%n", rs.getInt(1), truncate(rs.getString(2),35), rs.getString(3), nullToDash(rs.getString(4)), rs.getTimestamp(5));
            }
        } catch (SQLException e) { databaseError(e); }
    }

    private void listTickets(String filter) {
        String base = "SELECT t.ticket_id,v.title,v.severity,t.status,t.assigned_to,t.due_date FROM ticket t JOIN vulnerability v ON v.vuln_id=t.vuln_id";
        String sql = filter == null ? base + " ORDER BY t.ticket_id DESC" : base + " WHERE " + filter + " ORDER BY t.ticket_id DESC";
        try (Connection c = DBConnection.getInstance().getConnection(); PreparedStatement ps = c.prepareStatement(sql); ResultSet rs = ps.executeQuery()) {
            System.out.printf("%-6s %-30s %-10s %-12s %-10s %-12s%n", "TICKET", "TITLE", "SEVERITY", "STATUS", "ENGINEER", "DUE");
            while (rs.next()) System.out.printf("%-6d %-30s %-10s %-12s %-10s %-12s%n", rs.getInt(1), truncate(rs.getString(2),30), rs.getString(3), rs.getString(4), rs.getObject(5) == null ? "-" : rs.getInt(5), rs.getDate(6));
        } catch (SQLException e) { databaseError(e); }
    }

    private void listOverdue(int engineerId) {
        String sql = "SELECT t.ticket_id,v.title,v.severity,t.status,t.due_date FROM ticket t JOIN vulnerability v ON v.vuln_id=t.vuln_id WHERE t.assigned_to=? AND t.due_date<CURRENT_DATE AND t.status NOT IN ('RESOLVED','CLOSED') ORDER BY t.due_date";
        try (Connection c = DBConnection.getInstance().getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setInt(1, engineerId);
            try (ResultSet rs = ps.executeQuery()) {
                System.out.printf("%-6s %-30s %-10s %-12s %-12s%n", "TICKET", "TITLE", "SEVERITY", "STATUS", "DUE");
                while (rs.next()) System.out.printf("%-6d %-30s %-10s %-12s %-12s%n", rs.getInt(1), truncate(rs.getString(2),30), rs.getString(3), rs.getString(4), rs.getDate(5));
            }
        } catch (SQLException e) { databaseError(e); }
    }

    private void viewTicketDetails() {
        try {
            int ticketId = integer("Ticket ID: ");
            String sql = "SELECT t.ticket_id,v.title,v.description,v.severity,v.cve_id,v.reported_by,t.assigned_to,t.status,t.created_at,t.due_date FROM ticket t JOIN vulnerability v ON v.vuln_id=t.vuln_id WHERE t.ticket_id=?";
            try (Connection c = DBConnection.getInstance().getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
                ps.setInt(1, ticketId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) { System.out.println("Ticket not found."); return; }
                    System.out.println("\nTicket #" + rs.getInt(1));
                    System.out.println("Title: " + rs.getString(2));
                    System.out.println("Description: " + rs.getString(3));
                    System.out.println("Severity: " + rs.getString(4));
                    System.out.println("CVE: " + nullToDash(rs.getString(5)));
                    System.out.println("Reported by: " + rs.getInt(6));
                    System.out.println("Assigned to: " + (rs.getObject(7) == null ? "Unassigned" : rs.getInt(7)));
                    System.out.println("Status: " + rs.getString(8));
                    System.out.println("Created: " + rs.getTimestamp(9));
                    System.out.println("Due: " + rs.getDate(10));
                }
            }
            listComments(ticketId);
        } catch (SQLException | RuntimeException e) { System.out.println("Could not load ticket: " + e.getMessage()); }
    }

    private void listComments(int ticketId) throws SQLException {
        String sql = "SELECT c.comment_id,u.username,c.text,c.created_at FROM comment c JOIN users u ON u.user_id=c.user_id WHERE c.ticket_id=? ORDER BY c.created_at";
        try (Connection c = DBConnection.getInstance().getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setInt(1,ticketId);
            try (ResultSet rs=ps.executeQuery()) {
                System.out.println("Comments:");
                boolean any=false;
                while(rs.next()){ any=true; System.out.printf("  #%d [%s] %s: %s%n",rs.getInt(1),rs.getTimestamp(4),rs.getString(2),rs.getString(3)); }
                if(!any) System.out.println("  No comments.");
            }
        }
    }

    private void listAuditLog() {
        String sql = "SELECT a.log_id,u.username,a.action,a.details,a.created_at FROM audit_log a JOIN users u ON u.user_id=a.user_id ORDER BY a.log_id DESC LIMIT 100";
        try (Connection c=DBConnection.getInstance().getConnection(); PreparedStatement ps=c.prepareStatement(sql); ResultSet rs=ps.executeQuery()) {
            while(rs.next()) System.out.printf("#%d [%s] %s - %s (%s)%n",rs.getInt(1),rs.getString(2),rs.getString(3),rs.getString(4),rs.getTimestamp(5));
        } catch(SQLException e){databaseError(e);}
    }

    private Severity parseSeverity(String value) { try { return Severity.valueOf(value.trim().toUpperCase()); } catch(Exception e){ throw new IllegalArgumentException("Invalid severity"); } }
    private String prompt(String message) { System.out.print(message); return scanner.nextLine().trim(); }
    private String required(String message) { String v=prompt(message); if(v.isBlank()) throw new IllegalArgumentException("Value is required"); return v; }
    private int integer(String message) { try{return Integer.parseInt(required(message));}catch(NumberFormatException e){throw new IllegalArgumentException("Enter a valid integer");} }
    private static String truncate(String s,int n){return s==null?"":s.length()<=n?s:s.substring(0,n-1)+"…";}
    private static String nullToDash(String s){return s==null||s.isBlank()?"-":s;}
    private static void databaseError(SQLException e){System.out.println("Database error: " + e.getMessage());}
}
