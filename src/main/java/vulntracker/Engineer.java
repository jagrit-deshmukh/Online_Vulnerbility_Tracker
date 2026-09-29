package vulntracker;
import java.time.LocalDateTime;
public final class Engineer extends User {
    public Engineer(int id, String username, String name, String hash, LocalDateTime createdAt) { super(id, username, name, hash, createdAt); }
    public String getRole() { return "ENGINEER"; }
    public String getDashboard() { return "Engineer Dashboard: assigned tickets and remediation"; }
}
