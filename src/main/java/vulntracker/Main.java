package vulntracker;

import vulntracker.web.WebApp;

import java.time.LocalDate;
import java.util.Scanner;

public final class Main {
    private Main() {}
    public static void main(String[] args) throws Exception {
        if (args.length > 0 && "web".equalsIgnoreCase(args[0])) {
            WebApp.main(new String[0]);
            return;
        }
        System.out.println("Online Vulnerability / Ticket Tracker");
        System.out.println("Java 17 application initialized.");
        for (Severity s : Severity.values()) System.out.printf("%-8s SLA: %d day(s)%n", s, s.getSlaDays());
        System.out.println("Sample Critical due date: " + LocalDate.now().plusDays(Severity.CRITICAL.getSlaDays()));
        try (Scanner scanner = new Scanner(System.in)) {
            new ConsoleApp(scanner).run();
        }
    }
}
