package vulntracker;

import static org.junit.jupiter.api.Assertions.*;
import java.time.LocalDate;
import org.junit.jupiter.api.Test;

class TicketTest {
    @Test void criticalSlaIsOneDay() {
        Ticket t = new Ticket(1, 1, null, TicketStatus.OPEN, null, LocalDate.now().plusDays(Severity.CRITICAL.getSlaDays()));
        assertEquals(LocalDate.now().plusDays(1), t.getDueDate());
    }

    @Test void closedTicketIsNeverOverdue() {
        Ticket t = new Ticket(1, 1, null, TicketStatus.CLOSED, null, LocalDate.now().minusDays(1));
        assertFalse(t.isOverdue());
    }

    @Test void passwordVerificationUsesStoredHash() {
        String hash = PasswordUtil.hash("StrongPass123!");
        assertTrue(PasswordUtil.verify("StrongPass123!", hash));
        assertFalse(PasswordUtil.verify("wrong-password", hash));
    }
}
