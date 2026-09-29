package vulntracker;

import java.time.LocalDateTime;
import java.util.Objects;

public abstract class User {
    private final int userId;
    private final String username;
    private final String fullName;
    private final String passwordHash;
    private final LocalDateTime createdAt;

    protected User(int userId, String username, String fullName, String passwordHash, LocalDateTime createdAt) {
        if (username == null || username.isBlank()) throw new IllegalArgumentException("Username is required");
        if (fullName == null || fullName.isBlank()) throw new IllegalArgumentException("Full name is required");
        this.userId = userId;
        this.username = username;
        this.fullName = fullName;
        this.passwordHash = Objects.requireNonNull(passwordHash, "passwordHash");
        this.createdAt = createdAt;
    }
    public abstract String getRole();
    public abstract String getDashboard();
    public int getUserId() { return userId; }
    public String getUsername() { return username; }
    public String getFullName() { return fullName; }
    public String getPasswordHash() { return passwordHash; }
    public LocalDateTime getCreatedAt() { return createdAt; }
}
