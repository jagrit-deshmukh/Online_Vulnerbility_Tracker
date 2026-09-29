package vulntracker;

import java.time.LocalDate;
import java.time.LocalDateTime;

public final class Ticket {
    private final int ticketId;
    private final int vulnId;
    private Integer assignedTo;
    private TicketStatus status;
    private final LocalDateTime createdAt;
    private LocalDate dueDate;

    public Ticket(int ticketId, int vulnId, Integer assignedTo, TicketStatus status, LocalDateTime createdAt, LocalDate dueDate) {
        if (vulnId <= 0) throw new IllegalArgumentException("Invalid vulnerability id");
        this.ticketId = ticketId; this.vulnId = vulnId; this.assignedTo = assignedTo;
        this.status = status == null ? TicketStatus.OPEN : status; this.createdAt = createdAt; this.dueDate = dueDate;
    }
    public boolean isOverdue() { return !isClosedOrResolved() && dueDate != null && LocalDate.now().isAfter(dueDate); }
    private boolean isClosedOrResolved() { return status == TicketStatus.RESOLVED || status == TicketStatus.CLOSED; }
    public void assignTo(int engineerId) { if (engineerId <= 0) throw new IllegalArgumentException("Invalid engineer id"); assignedTo = engineerId; }
    public void updateStatus(TicketStatus newStatus) {
        if (newStatus == null) throw new IllegalArgumentException("Status is required");
        if (status == TicketStatus.CLOSED && newStatus != TicketStatus.CLOSED) throw new IllegalStateException("Closed ticket cannot be reopened");
        status = newStatus;
    }
    public int getTicketId() { return ticketId; }
    public int getVulnId() { return vulnId; }
    public Integer getAssignedTo() { return assignedTo; }
    public TicketStatus getStatus() { return status; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDate getDueDate() { return dueDate; }
}
