package vulntracker;
import java.time.LocalDateTime;
public final class Analyst extends User {
    public Analyst(int id, String username, String name, String hash, LocalDateTime createdAt) { super(id, username, name, hash, createdAt); }
    public String getRole() { return "ANALYST"; }
    public String getDashboard() { return "Analyst Dashboard: report and track vulnerabilities"; }
}
