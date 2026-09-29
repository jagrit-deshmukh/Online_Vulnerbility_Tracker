package vulntracker;
import java.time.LocalDateTime;
public final class Admin extends User {
    public Admin(int id, String username, String name, String hash, LocalDateTime createdAt) { super(id, username, name, hash, createdAt); }
    public String getRole() { return "ADMIN"; }
    public String getDashboard() { return "Admin Dashboard: users, tickets, audit logs, reports"; }
}
