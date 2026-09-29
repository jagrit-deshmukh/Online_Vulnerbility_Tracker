package vulntracker;
import java.time.LocalDateTime;
public record Comment(int commentId, int ticketId, int userId, String text, LocalDateTime createdAt) {
    public Comment {
        if (ticketId <= 0 || userId <= 0) throw new IllegalArgumentException("Invalid comment reference");
        if (text == null || text.isBlank()) throw new IllegalArgumentException("Comment text is required");
    }
}
