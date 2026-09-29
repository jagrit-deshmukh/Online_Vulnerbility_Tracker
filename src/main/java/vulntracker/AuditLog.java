package vulntracker;
import java.time.LocalDateTime;
public record AuditLog(int logId, int userId, String action, String details, LocalDateTime createdAt) {
    public AuditLog {
        if (userId <= 0) throw new IllegalArgumentException("Invalid user id");
        if (action == null || action.isBlank()) throw new IllegalArgumentException("Action is required");
    }
}
