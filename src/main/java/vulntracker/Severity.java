package vulntracker;

public enum Severity {
    CRITICAL(1), HIGH(3), MEDIUM(7), LOW(30);

    private final int slaDays;
    Severity(int slaDays) { this.slaDays = slaDays; }
    public int getSlaDays() { return slaDays; }
}
