package vulntracker;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
class SeverityTest {
 @Test void slaMappingIsCorrect(){assertEquals(1,Severity.CRITICAL.getSlaDays());assertEquals(3,Severity.HIGH.getSlaDays());assertEquals(7,Severity.MEDIUM.getSlaDays());assertEquals(30,Severity.LOW.getSlaDays());}
 @Test void overdueFalseWhenResolved(){Ticket t=new Ticket(1,1,null,TicketStatus.RESOLVED,null,java.time.LocalDate.now().minusDays(1));assertFalse(t.isOverdue());}
}
