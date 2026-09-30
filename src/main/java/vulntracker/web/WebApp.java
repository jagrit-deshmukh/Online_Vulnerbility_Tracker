package vulntracker.web;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import vulntracker.*;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.time.Duration;
import java.time.LocalDate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/** Minimal dependency-light web UI using Java's built-in HTTP server. */
public final class WebApp {
    private static final int PORT = Integer.parseInt(System.getenv().getOrDefault("VULNTRACKER_WEB_PORT", "8080"));
    private static final Map<String, Session> SESSIONS = new ConcurrentHashMap<>();
    private record Session(User user, String csrf) {}
    private static final AuthService AUTH = new AuthService();
    private static final VulnerabilityService VULNS = new VulnerabilityService();
    private static final TicketService TICKETS = new TicketService();
    private static final CommentDao COMMENTS = new CommentDao();
    private static final UserDao USERS = new UserDao();
    private static final AuditLogDao AUDIT = new AuditLogDao();

    private WebApp() {}

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        server.createContext("/", WebApp::handle);
        server.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(8));
        System.out.println("VulnTracker web UI: http://localhost:" + PORT);
        server.start();
    }

    private static void handle(HttpExchange ex) throws IOException {
        try {
            String path = ex.getRequestURI().getPath();
            String method = ex.getRequestMethod();
            User user = currentUser(ex);
            if ("GET".equals(method) && "/".equals(path)) { redirect(ex, user == null ? "/login" : "/dashboard"); return; }
            if ("GET".equals(method) && "/login".equals(path)) { send(ex, 200, loginPage(null)); return; }
            if ("POST".equals(method) && "/login".equals(path)) { login(ex); return; }
            if ("POST".equals(method) && "/logout".equals(path)) { logout(ex); return; }
            if (user == null) { redirect(ex, "/login"); return; }
            if ("GET".equals(method) && "/dashboard".equals(path)) { send(ex, 200, dashboard(user)); return; }
            if ("GET".equals(method) && "/ticket".equals(path)) { send(ex, 200, ticketPage(ex, user)); return; }
            if ("GET".equals(method) && "/admin/users".equals(path)) { requireRole(user, "ADMIN"); send(ex, 200, page("User management", user, userManagement(user))); return; }
            if ("POST".equals(method) && "/admin/users".equals(path)) {adminCreateUser(ex, user);return; }
            if ("POST".equals(method) && "/analyst/report".equals(path)) { analystReport(ex, user); return; }
            if ("POST".equals(method) && "/admin/assign".equals(path)) { adminAssign(ex, user); return; }
            if ("POST".equals(method) && "/engineer/status".equals(path)) { engineerStatus(ex, user); return; }
            if ("POST".equals(method) && "/ticket/comment".equals(path)) { addComment(ex, user); return; }
            send(ex, 404, page("Not found", user, "<div class='card'><h2>404</h2><p>Page not found.</p></div>"));
        } catch (SecurityException e) { send(ex, 403, page("Forbidden", currentUser(ex), alert(e.getMessage(), "danger"))); }
        catch (IllegalArgumentException e) { send(ex, 400, page("Invalid request", currentUser(ex), alert(e.getMessage(), "danger"))); }
        catch (SQLException e) {
    e.printStackTrace();
    User user = currentUser(ex);

    if (user == null) {
        send(ex, 500, loginPage("Database operation failed. Check the server configuration and database availability."));
    } else {
        send(ex, 500, page("Database error", user,
                alert("Database operation failed. Check the server configuration and database availability.", "danger")));
    }
}
catch (Exception e) {
    e.printStackTrace();
    User user = currentUser(ex);

    if (user == null) {
        send(ex, 500, loginPage("Unexpected server error."));
    } else {
        send(ex, 500, page("Server error", user,
                alert("Unexpected server error.", "danger")));
    }
}
    }

    private static void login(HttpExchange ex) throws Exception {
        Map<String,String> f = form(ex);
        String username = required(f, "username", 50);
        String password = required(f, "password", 128);
        Optional<User> found = AUTH.login(username, password);
        if (found.isEmpty()) { send(ex, 401, loginPage("Invalid username or password.")); return; }
        String token = UUID.randomUUID().toString();
        SESSIONS.put(token, new Session(found.get(), UUID.randomUUID().toString()));
        ex.getResponseHeaders().add("Set-Cookie", "VULNTRACKER_SESSION=" + token + "; Path=/; HttpOnly; SameSite=Lax");
        redirect(ex, "/dashboard");
    }

    private static void verifyCsrf(HttpExchange ex, Map<String,String> f) { Session s=currentSession(ex); if(s==null || !Objects.equals(s.csrf(), f.get("csrf"))) throw new SecurityException("Invalid request token"); }

    private static void logout(HttpExchange ex) throws IOException {
        try { verifyCsrf(ex, form(ex)); } catch (Exception e) { throw new IOException(e); }
        String token = cookie(ex, "VULNTRACKER_SESSION");
        if (token != null) SESSIONS.remove(token);
        ex.getResponseHeaders().add("Set-Cookie", "VULNTRACKER_SESSION=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
        redirect(ex, "/login");
    }

    private static void analystReport(HttpExchange ex, User user) throws Exception {
        requireRole(user, "ANALYST");
        Map<String,String> f = form(ex);
        verifyCsrf(ex, f);
        String title = required(f, "title", 200);
        String description = required(f, "description", 5000);
        String severity = required(f, "severity", 10).toUpperCase(Locale.ROOT);
        String cve = optional(f, "cve", 30);
        Severity s = Severity.valueOf(severity);
        Vulnerability v = new Vulnerability(0, title, description, s, cve, user.getUserId(), null);
        int ticketId = VULNS.report(user, v);
        redirectWithMessage(ex, "/dashboard", "Vulnerability reported successfully. Ticket #" + ticketId + " was created.");
    }

    private static void adminAssign(HttpExchange ex, User user) throws Exception {
        requireRole(user, "ADMIN");
        Map<String,String> f = form(ex);
        verifyCsrf(ex, f);
        int ticketId = positiveInt(f, "ticketId");
        int engineerId = positiveInt(f, "engineerId");
        TICKETS.assign(user, ticketId, engineerId);
        redirectWithMessage(ex, "/dashboard", "Ticket #" + ticketId + " assigned successfully.");
    }

    private static void engineerStatus(HttpExchange ex, User user) throws Exception {
        requireRole(user, "ENGINEER");
        Map<String,String> f = form(ex);
        verifyCsrf(ex, f);
        int ticketId = positiveInt(f, "ticketId");
        TicketStatus status = TicketStatus.valueOf(required(f, "status", 20).toUpperCase(Locale.ROOT));
        TICKETS.updateStatus(user, ticketId, status);
        redirectWithMessage(ex, "/dashboard", "Ticket #" + ticketId + " updated to " + status + ".");
    }

    private static void addComment(HttpExchange ex, User user) throws Exception {
        Map<String,String> f = form(ex);
        verifyCsrf(ex, f);
        int ticketId = positiveInt(f, "ticketId");
        authorizeTicketInteraction(user, ticketId);
        String text = required(f, "text", 3000);
        COMMENTS.create(ticketId, user.getUserId(), text);
        redirectWithMessage(ex, "/dashboard", "Comment added to ticket #" + ticketId + ".");
    }

    private static String dashboard(User user) throws SQLException {
        String body = switch (user.getRole()) {
            case "ADMIN" -> adminDashboard(user);
            case "ANALYST" -> analystDashboard(user);
            case "ENGINEER" -> engineerDashboard(user);
            default -> alert("Unsupported role.", "danger");
        };
        return page("Dashboard", user, body);
    }

    private static String adminDashboard(User user) throws SQLException {
        String csrf=csrfFor(user);
        List<Map<String,Object>> tickets = query("SELECT t.ticket_id,v.title,v.severity,t.status,t.due_date,t.assigned_to,u.full_name AS engineer FROM ticket t JOIN vulnerability v ON v.vuln_id=t.vuln_id LEFT JOIN users u ON u.user_id=t.assigned_to ORDER BY t.ticket_id DESC");
        List<Map<String,Object>> engineers = query("SELECT user_id,full_name,username FROM users WHERE role='ENGINEER' ORDER BY full_name");
        List<Map<String,Object>> logs = query("SELECT a.created_at,a.action,a.details,u.username FROM audit_log a JOIN users u ON u.user_id=a.user_id ORDER BY a.created_at DESC LIMIT 15");
        StringBuilder b = new StringBuilder();
        b.append(stats(tickets));
        b.append("<div class='toolbar'><a class='btn ghost' href='/admin/users'>Manage users</a></div>");
        b.append("<div class='grid two'><section class='card'><div class='section-head'><h2>Tickets</h2><span class='muted'>All tickets</span></div><div class='table-wrap'><table><tr><th>ID</th><th>Finding</th><th>Severity</th><th>Status</th><th>SLA due</th><th>Engineer</th><th>Assign</th></tr>");
        for (Map<String,Object> t : tickets) {
            b.append("<tr><td>#").append(t.get("ticket_id")).append("</td><td><a class='ticket-link' href='/ticket?id=").append(t.get("ticket_id")).append("'>").append(e(t.get("title"))).append("</a></td><td>").append(badge(t.get("severity"))).append("</td><td>").append(statusBadge(t.get("status"))).append("</td><td>").append(e(t.get("due_date"))).append("</td><td>").append(e(t.get("engineer") == null ? "Unassigned" : t.get("engineer"))).append("</td><td>");
            b.append("<form class='inline-form' method='post' action='/admin/assign'><input type='hidden' name='csrf' value='"+csrf+"'><input type='hidden' name='ticketId' value='").append(t.get("ticket_id")).append("'><select name='engineerId'>");
            for (Map<String,Object> eng : engineers) b.append("<option value='").append(eng.get("user_id")).append("'").append(Objects.equals(t.get("assigned_to"), eng.get("user_id")) ? " selected" : "").append(">" ).append(e(eng.get("full_name"))).append("</option>");
            b.append("</select><button class='btn small' type='submit'>Assign</button></form></td></tr>");
        }
        b.append("</table></div></section>");
        b.append("<section class='card'><div class='section-head'><h2>Audit log</h2><span class='muted'>Latest 15</span></div><div class='activity'>");
        for (Map<String,Object> l : logs) b.append("<div class='activity-row'><div class='dot'></div><div><strong>").append(e(l.get("action"))).append("</strong><p>").append(e(l.get("details"))).append("</p><small>").append(e(l.get("username"))).append(" · ").append(e(l.get("created_at"))).append("</small></div></div>");
        b.append("</div></section></div>");
        return b.toString();
    }

    private static String analystDashboard(User user) throws SQLException {
        String csrf=csrfFor(user);
        List<Map<String,Object>> tickets = query("SELECT t.ticket_id,v.title,v.severity,t.status,t.due_date,t.created_at FROM ticket t JOIN vulnerability v ON v.vuln_id=t.vuln_id WHERE v.reported_by=? ORDER BY t.ticket_id DESC", user.getUserId());
        StringBuilder b = new StringBuilder();
        b.append("<div class='grid two'><section class='card'><div class='section-head'><h2>Report vulnerability</h2><span class='muted'>Ticket is created automatically</span></div><form method='post' action='/analyst/report'><input type='hidden' name='csrf' value='"+csrf+"'><label>Title<input name='title' maxlength='200' required></label><label>Description<textarea name='description' maxlength='5000' required></textarea></label><div class='grid two compact'><label>Severity<select name='severity'><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></label><label>CVE ID <span class='muted'>(optional)</span><input name='cve' maxlength='30' placeholder='CVE-2026-1234'></label></div><button class='btn' type='submit'>Create ticket</button></form></section>");
        b.append("<section class='card'><div class='section-head'><h2>My findings</h2><span class='muted'>").append(tickets.size()).append(" tickets</span></div><div class='table-wrap'><table><tr><th>ID</th><th>Finding</th><th>Severity</th><th>Status</th><th>Due</th></tr>");
        for (Map<String,Object> t : tickets) b.append("<tr><td>#").append(t.get("ticket_id")).append("</td><td><a class='ticket-link' href='/ticket?id=").append(t.get("ticket_id")).append("'>").append(e(t.get("title"))).append("</a></td><td>").append(badge(t.get("severity"))).append("</td><td>").append(statusBadge(t.get("status"))).append("</td><td>").append(e(t.get("due_date"))).append("</td></tr>");
        b.append("</table></div></section></div>");
        return b.toString();
    }

    private static String engineerDashboard(User user) throws SQLException {
        String csrf=csrfFor(user);
       List<Map<String,Object>> tickets = query(
    "SELECT t.ticket_id,v.title,v.description,v.severity,t.status,t.due_date,t.created_at " +
    "FROM ticket t JOIN vulnerability v ON v.vuln_id=t.vuln_id " +
    "WHERE t.assigned_to=? AND t.status <> 'CLOSED' " +
    "ORDER BY t.due_date ASC",
    user.getUserId()
);
        StringBuilder b = new StringBuilder();
        b.append("<section class='card'><div class='section-head'><h2>Assigned tickets</h2><span class='muted'>").append(tickets.size()).append(" tickets</span></div><div class='ticket-list'>");
       for (Map<String,Object> t : tickets) {
    String currentStatus = String.valueOf(t.get("status"));

    String statusOptions;
    switch (currentStatus) {
        case "OPEN" -> statusOptions =
                "<option selected>OPEN</option>" +
                "<option>IN_PROGRESS</option>";

        case "IN_PROGRESS" -> statusOptions =
                "<option>IN_PROGRESS</option>" +
                "<option>RESOLVED</option>";

        case "RESOLVED" -> statusOptions =
                "<option>RESOLVED</option>" +
                "<option>CLOSED</option>";

        case "CLOSED" -> statusOptions =
                "<option selected>CLOSED</option>";

        default -> statusOptions =
                "<option selected>" + e(currentStatus) + "</option>";
    }

    b.append("<article class='ticket'><div class='ticket-top'><div><span class='eyebrow'>Ticket #")
            .append(t.get("ticket_id"))
            .append("</span><h3>")
            .append(e(t.get("title")))
            .append("</h3></div><div>")
            .append(badge(t.get("severity")))
            .append(" ")
            .append(statusBadge(t.get("status")))
            .append("</div></div><p>")
            .append(e(t.get("description")))
            .append("</p><div class='meta'><span>Due: <strong>")
            .append(e(t.get("due_date")))
            .append("</strong></span><span>Created: ")
            .append(e(t.get("created_at")))
            .append("</span></div><div class='actions'>")

            .append("<form class='inline-form' method='post' action='/engineer/status'>")
            .append("<input type='hidden' name='csrf' value='").append(csrf).append("'>")
            .append("<input type='hidden' name='ticketId' value='").append(t.get("ticket_id")).append("'>")
            .append("<select name='status'>")
            .append(statusOptions)
            .append("</select>")
            .append("<button class='btn small' type='submit'>Update</button>")
            .append("</form>")

            .append("<form class='comment-form' method='post' action='/ticket/comment'>")
            .append("<input type='hidden' name='csrf' value='").append(csrf).append("'>")
            .append("<input type='hidden' name='ticketId' value='").append(t.get("ticket_id")).append("'>")
            .append("<input name='text' maxlength='3000' placeholder='Add remediation note...' required>")
            .append("<button class='btn ghost small'>Comment</button>")
            .append("</form>")

            .append("</div></article>");
}
        b.append("</div></section>");
        return b.toString();
    }

    private static String ticketPage(HttpExchange ex, User user) throws SQLException {
        int ticketId = positiveInt(queryParams(ex), "id");
        List<Map<String,Object>> rows = query("SELECT t.ticket_id,t.status,t.due_date,t.created_at,t.assigned_to,v.title,v.description,v.severity,v.cve_id,v.reported_by, reporter.full_name AS reporter_name, engineer.full_name AS engineer_name FROM ticket t JOIN vulnerability v ON v.vuln_id=t.vuln_id JOIN users reporter ON reporter.user_id=v.reported_by LEFT JOIN users engineer ON engineer.user_id=t.assigned_to WHERE t.ticket_id=?", ticketId);
        if (rows.isEmpty()) throw new IllegalArgumentException("Ticket not found");
        Map<String,Object> t = rows.get(0);
        boolean allowed = "ADMIN".equals(user.getRole()) || Objects.equals(((Number)t.get("reported_by")).intValue(), user.getUserId()) || (t.get("assigned_to") != null && Objects.equals(((Number)t.get("assigned_to")).intValue(), user.getUserId()));
        if (!allowed) throw new SecurityException("You are not allowed to view this ticket");
       List<Map<String,Object>> comments = query("SELECT c.created_at,c.text AS comment_text,u.full_name FROM comment c JOIN users u ON u.user_id=c.user_id WHERE c.ticket_id=? ORDER BY c.created_at ASC", ticketId);
        StringBuilder b = new StringBuilder();
        b.append("<a class='back-link' href='/dashboard'>← Back to dashboard</a>");
        b.append("<section class='card ticket-detail'><div class='ticket-top'><div><span class='eyebrow'>Ticket #").append(ticketId).append("</span><h2>").append(e(t.get("title"))).append("</h2></div><div>").append(badge(t.get("severity"))).append(" ").append(statusBadge(t.get("status"))).append("</div></div>");
        b.append("<div class='meta'><span>Reported by: ").append(e(t.get("reporter_name"))).append("</span><span>Engineer: ").append(e(t.get("engineer_name") == null ? "Unassigned" : t.get("engineer_name"))).append("</span><span>Due: ").append(e(t.get("due_date"))).append("</span><span>CVE: ").append(e(t.get("cve_id") == null ? "—" : t.get("cve_id"))).append("</span></div>");
        b.append("<p class='description'>").append(e(t.get("description"))).append("</p></section>");
        b.append("<section class='card'><div class='section-head'><h2>Activity</h2><span class='muted'>").append(comments.size()).append(" comments</span></div><div class='activity'>");
        for (Map<String,Object> c : comments) b.append("<div class='activity-row'><div class='dot'></div><div><strong>").append(e(c.get("full_name"))).append("</strong><p>").append(e(c.get("comment_text"))).append("</p><small>").append(e(c.get("created_at"))).append("</small></div></div>");
        if (comments.isEmpty()) b.append("<p class='muted'>No comments yet.</p>");
        b.append("</div></section>");
        if ("ADMIN".equals(user.getRole()) || "ENGINEER".equals(user.getRole()) || Objects.equals(((Number)t.get("reported_by")).intValue(), user.getUserId())) {
            b.append("<section class='card'><form class='comment-form wide' method='post' action='/ticket/comment'><input type='hidden' name='csrf' value='").append(csrfFor(user)).append("'><input type='hidden' name='ticketId' value='").append(ticketId).append("'><input name='text' maxlength='3000' placeholder='Add a remediation note...' required><button class='btn' type='submit'>Add comment</button></form></section>");
        }
        return page("Ticket #" + ticketId, user, b.toString());
    }

    private static void adminCreateUser(HttpExchange ex, User user) throws Exception {
    requireRole(user, "ADMIN");

    Map<String, String> f = form(ex);
    verifyCsrf(ex, f);

    String fullName = required(f, "fullName", 100);
    String username = required(f, "username", 50);
    String password = required(f, "password", 128);
    String confirmPassword = required(f, "confirmPassword", 128);
    String role = required(f, "role", 20).toUpperCase(Locale.ROOT);

    if (!password.equals(confirmPassword)) {
        throw new IllegalArgumentException("Passwords do not match.");
    }

    if (!Set.of("ADMIN", "ANALYST", "ENGINEER").contains(role)) {
        throw new IllegalArgumentException("Invalid user role.");
    }

    if (password.length() < 8) {
        throw new IllegalArgumentException("Password must be at least 8 characters.");
    }

    try (Connection c = DBConnection.getInstance().getConnection()) {
        c.setAutoCommit(false);

        try {
            int userId = USERS.create(c, username, fullName, password, role);

            AUDIT.record(
                    c,
                    user.getUserId(),
                    "USER_CREATED",
                    "Created user #" + userId +
                            " (" + username + ") with role " + role
            );

            c.commit();

            redirectWithMessage(
                    ex,
                    "/admin/users",
                    "User " + username + " was created successfully."
            );
        } catch (Exception e) {
            c.rollback();

            if (e instanceof SQLException sqlException
                    && "23000".equals(sqlException.getSQLState())) {
                throw new IllegalArgumentException(
                        "Username already exists."
                );
            }

            throw e;
        }
    }
}

    private static String userManagement(User user) throws SQLException {
    List<Map<String, Object>> users = query(
            "SELECT user_id,username,full_name,role,created_at " +
            "FROM users ORDER BY role,full_name"
    );

    String csrf = csrfFor(user);

    StringBuilder b = new StringBuilder();

    b.append("<div class='grid two'>");

    // User list
    b.append("<section class='card'>")
            .append("<div class='section-head'>")
            .append("<h2>Users</h2>")
            .append("<span class='muted'>")
            .append(users.size())
            .append(" accounts</span>")
            .append("</div>");

    b.append("<div class='table-wrap'><table>")
            .append("<tr>")
            .append("<th>Name</th>")
            .append("<th>Username</th>")
            .append("<th>Role</th>")
            .append("<th>Created</th>")
            .append("</tr>");

    for (Map<String, Object> u : users) {
        b.append("<tr>")
                .append("<td>").append(e(u.get("full_name"))).append("</td>")
                .append("<td>").append(e(u.get("username"))).append("</td>")
                .append("<td>").append(e(u.get("role"))).append("</td>")
                .append("<td>").append(e(u.get("created_at"))).append("</td>")
                .append("</tr>");
    }

    b.append("</table></div>")
            .append("</section>");

    // Create user
    b.append("<section class='card'>")
            .append("<div class='section-head'>")
            .append("<h2>Create user</h2>")
            .append("<span class='muted'>Admin only</span>")
            .append("</div>")

            .append("<form method='post' action='/admin/users'>")

            .append("<input type='hidden' name='csrf' value='")
            .append(csrf)
            .append("'>")

            .append("<label>Full name")
            .append("<input name='fullName' maxlength='100' required>")
            .append("</label>")

            .append("<label>Username")
            .append("<input name='username' maxlength='50' autocomplete='username' required>")
            .append("</label>")

            .append("<label>Password")
            .append("<input type='password' name='password' maxlength='128' minlength='8' autocomplete='new-password' required>")
            .append("</label>")

            .append("<label>Confirm password")
            .append("<input type='password' name='confirmPassword' maxlength='128' minlength='8' autocomplete='new-password' required>")
            .append("</label>")

            .append("<label>Role")
            .append("<select name='role' required>")
            .append("<option value='ANALYST'>ANALYST</option>")
            .append("<option value='ENGINEER'>ENGINEER</option>")
            .append("<option value='ADMIN'>ADMIN</option>")
            .append("</select>")
            .append("</label>")

            .append("<button class='btn' type='submit'>Create user</button>")

            .append("</form>")
            .append("</section>");

    b.append("</div>");

    return b.toString();
}

    private static Map<String,String> queryParams(HttpExchange ex) {
        return parseEncodedForm(ex.getRequestURI().getRawQuery() == null ? "" : ex.getRequestURI().getRawQuery());
    }

    private static String stats(List<Map<String,Object>> tickets) {
        long open=tickets.stream().filter(t->!"RESOLVED".equals(t.get("status"))&&!"CLOSED".equals(t.get("status"))).count();
        long overdue=tickets.stream().filter(WebApp::overdue).count();
        long critical=tickets.stream().filter(t->"CRITICAL".equals(t.get("severity"))).count();
        long resolved=tickets.stream().filter(t->"RESOLVED".equals(t.get("status"))||"CLOSED".equals(t.get("status"))).count();
        return "<div class='stats'><div class='stat'><span>Total</span><strong>"+tickets.size()+"</strong></div><div class='stat'><span>Active</span><strong>"+open+"</strong></div><div class='stat'><span>Critical</span><strong>"+critical+"</strong></div><div class='stat'><span>Resolved</span><strong>"+resolved+"</strong></div><div class='stat warning'><span>Overdue</span><strong>"+overdue+"</strong></div></div>";
    }

    private static boolean overdue(Map<String,Object> t) { Object d=t.get("due_date"); return d instanceof java.sql.Date && LocalDate.now().isAfter(((java.sql.Date)d).toLocalDate()) && !"RESOLVED".equals(t.get("status")) && !"CLOSED".equals(t.get("status")); }

    private static List<Map<String,Object>> query(String sql, Object... args) throws SQLException {
        try (Connection c=DBConnection.getInstance().getConnection(); PreparedStatement ps=c.prepareStatement(sql)) {
            for(int i=0;i<args.length;i++) ps.setObject(i+1,args[i]);
            try(ResultSet rs=ps.executeQuery()) { List<Map<String,Object>> out=new ArrayList<>(); ResultSetMetaData md=rs.getMetaData(); while(rs.next()){Map<String,Object> row=new LinkedHashMap<>(); for(int i=1;i<=md.getColumnCount();i++) row.put(md.getColumnLabel(i),rs.getObject(i)); out.add(row);} return out; }
        }
    }

    private static Session currentSession(HttpExchange ex) { String token=cookie(ex,"VULNTRACKER_SESSION"); return token==null?null:SESSIONS.get(token); }
    private static User currentUser(HttpExchange ex) { Session s=currentSession(ex); return s==null?null:s.user(); }
    private static String csrfFor(User user) {
        for (Session s : SESSIONS.values()) if (s.user().getUserId() == user.getUserId()) return s.csrf();
        throw new SecurityException("Session expired");
    }
    private static void authorizeTicketInteraction(User user, int ticketId) throws SQLException {
        if ("ADMIN".equals(user.getRole())) return;
        List<Map<String,Object>> rows=query("SELECT v.reported_by,t.assigned_to FROM ticket t JOIN vulnerability v ON v.vuln_id=t.vuln_id WHERE t.ticket_id=?",ticketId);
        if(rows.isEmpty()) throw new IllegalArgumentException("Ticket not found");
        Map<String,Object> r=rows.get(0);
        int reporter=((Number)r.get("reported_by")).intValue(); Object assigned=r.get("assigned_to");
        boolean allowed=("ANALYST".equals(user.getRole()) && reporter==user.getUserId()) || ("ENGINEER".equals(user.getRole()) && assigned!=null && ((Number)assigned).intValue()==user.getUserId());
        if(!allowed) throw new SecurityException("You are not allowed to modify this ticket");
    }
    private static void requireRole(User u,String role){if(u==null||!role.equals(u.getRole()))throw new SecurityException("Insufficient role");}

    private static Map<String,String> form(HttpExchange ex) throws IOException { return parseEncodedForm(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)); }
    private static Map<String,String> parseEncodedForm(String body) { Map<String,String> m=new LinkedHashMap<>(); if(body==null||body.isBlank())return m; for(String pair:body.split("&")){String[] p=pair.split("=",2);String k=URLDecoder.decode(p[0],StandardCharsets.UTF_8);String v=p.length>1?URLDecoder.decode(p[1],StandardCharsets.UTF_8):"";m.put(k,v);} return m; }
    private static String required(Map<String,String> m,String k,int max){String v=m.get(k);if(v==null||v.isBlank())throw new IllegalArgumentException(k+" is required");if(v.length()>max)throw new IllegalArgumentException(k+" is too long");return v.trim();}
    private static String optional(Map<String,String> m,String k,int max){String v=m.get(k);if(v==null||v.isBlank())return null;if(v.length()>max)throw new IllegalArgumentException(k+" is too long");return v.trim();}
    private static int positiveInt(Map<String,String> m,String k){try{int v=Integer.parseInt(required(m,k,12));if(v<=0)throw new NumberFormatException();return v;}catch(NumberFormatException e){throw new IllegalArgumentException(k+" must be a positive integer");}}
    private static String cookie(HttpExchange ex,String name){String h=ex.getRequestHeaders().getFirst("Cookie");if(h==null)return null;for(String p:h.split(";")){String[] a=p.trim().split("=",2);if(a.length==2&&a[0].equals(name))return a[1];}return null;}
    private static void redirect(HttpExchange ex,String path)throws IOException{ex.getResponseHeaders().set("Location",path);ex.sendResponseHeaders(302,-1);ex.close();}
    private static void redirectWithMessage(HttpExchange ex,String path,String msg)throws IOException{ex.getResponseHeaders().set("Location",path+"?message="+java.net.URLEncoder.encode(msg,StandardCharsets.UTF_8));ex.sendResponseHeaders(303,-1);ex.close();}
    private static void send(HttpExchange ex,int status,String html)throws IOException{byte[] b=html.getBytes(StandardCharsets.UTF_8);ex.getResponseHeaders().set("Content-Type","text/html; charset=UTF-8");ex.getResponseHeaders().set("Content-Security-Policy","default-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'");ex.getResponseHeaders().set("X-Content-Type-Options","nosniff");ex.getResponseHeaders().set("X-Frame-Options","DENY");ex.getResponseHeaders().set("Referrer-Policy","same-origin");ex.sendResponseHeaders(status,b.length);try(OutputStream os=ex.getResponseBody()){os.write(b);}}

    private static String loginPage(String error){return "<!doctype html><html><head>"+styles()+"</head><body class='login-shell'><main class='login-card'><div class='brand'><div class='brand-mark'>V</div><div><strong>VulnTracker</strong><span>Security remediation workspace</span></div></div><h1>Sign in</h1><p class='muted'>Manage vulnerability findings, SLAs and remediation.</p>"+(error==null?"":alert(error,"danger"))+"<form method='post' action='/login'><label>Username<input name='username' autocomplete='username' maxlength='50' required></label><label>Password<input type='password' name='password' autocomplete='current-password' maxlength='128' required></label><button class='btn full' type='submit'>Sign in</button></form><div class='login-note'>Java 17 · MySQL 8 · JDBC</div></main></body></html>";}
    private static String page(String title,User user,String body){String msg="";return "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"+styles()+"</head><body><header class='topbar'><a class='brand' href='/dashboard'><div class='brand-mark'>V</div><div><strong>VulnTracker</strong><span>Security remediation workspace</span></div></a><div class='userbox'><span>"+e(user.getFullName())+" · "+user.getRole()+"</span><form method='post' action='/logout'><input type='hidden' name='csrf' value='"+csrfFor(user)+"'><button class='link-btn'>Sign out</button></form></div></header><main class='container'><div class='page-head'><div><span class='eyebrow'>Dashboard</span><h1>"+title+"</h1></div></div>"+messageFromQuery(body)+body+"</main></body></html>";}
    private static String messageFromQuery(String body){return "";}
    private static String alert(String msg,String type){return "<div class='alert "+type+"'>"+e(msg)+"</div>";}
    private static String badge(Object s){String v=String.valueOf(s);return "<span class='badge sev-"+v.toLowerCase(Locale.ROOT)+"'>"+e(v)+"</span>";}
    private static String statusBadge(Object s){String v=String.valueOf(s);return "<span class='badge status-"+v.toLowerCase(Locale.ROOT)+"'>"+e(v.replace('_',' '))+"</span>";}
    private static String e(Object o){if(o==null)return "";return String.valueOf(o).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;").replace("'","&#39;");}

    private static String styles(){return "<style>:root{--bg:#0b1020;--panel:#11182a;--panel2:#172039;--text:#eef2ff;--muted:#8e9ab7;--line:#26314b;--accent:#7c9cff;--critical:#ff6b7a;--high:#ffad5c;--medium:#f2cf66;--low:#72d6a4;--danger:#ff6878}*{box-sizing:border-box}body{margin:0;background:linear-gradient(135deg,#0a0f1d,#10182a);color:var(--text);font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif}a{color:inherit;text-decoration:none}.topbar{height:72px;border-bottom:1px solid var(--line);background:rgba(11,16,32,.88);backdrop-filter:blur(16px);display:flex;align-items:center;justify-content:space-between;padding:0 32px;position:sticky;top:0;z-index:10}.brand{display:flex;gap:12px;align-items:center}.brand span{display:block;color:var(--muted);font-size:11px;margin-top:1px}.brand-mark{width:34px;height:34px;border-radius:10px;background:linear-gradient(135deg,#8da8ff,#5f7df2);display:grid;place-items:center;font-weight:800;color:#081027}.userbox{display:flex;align-items:center;gap:18px;color:var(--muted)}.link-btn{border:0;background:none;color:var(--text);cursor:pointer}.container{max-width:1400px;margin:0 auto;padding:36px 32px 60px}.page-head{display:flex;justify-content:space-between;align-items:end;margin-bottom:24px}h1{font-size:30px;letter-spacing:-.03em;margin:4px 0}h2{font-size:17px;margin:0}h3{font-size:18px;margin:5px 0}.eyebrow{text-transform:uppercase;letter-spacing:.12em;color:var(--accent);font-size:11px;font-weight:700}.muted{color:var(--muted)}.grid{display:grid;gap:18px}.grid.two{grid-template-columns:1.15fr .85fr}.grid.compact{gap:12px}.card{background:rgba(17,24,42,.86);border:1px solid var(--line);border-radius:16px;padding:20px;box-shadow:0 18px 50px rgba(0,0,0,.18);margin-bottom:18px}.section-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:18px}.stat{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px}.stat span{color:var(--muted);font-size:12px}.stat strong{display:block;font-size:26px;margin-top:4px}.stat.warning strong{color:var(--critical)}table{width:100%;border-collapse:collapse}th,td{padding:12px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:middle}th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}tr:last-child td{border-bottom:0}.table-wrap{overflow:auto}.badge{display:inline-flex;align-items:center;padding:4px 8px;border-radius:999px;font-size:11px;font-weight:700;white-space:nowrap;background:#24304a;color:#cfd7ea}.sev-critical{background:rgba(255,107,122,.14);color:var(--critical)}.sev-high{background:rgba(255,173,92,.14);color:var(--high)}.sev-medium{background:rgba(242,207,102,.14);color:var(--medium)}.sev-low{background:rgba(114,214,164,.14);color:var(--low)}.status-open{color:#b7c4df}.status-in_progress{color:#8db0ff}.status-resolved{color:var(--low)}.status-closed{color:#aab2c4}.btn{border:0;border-radius:10px;padding:10px 15px;background:var(--accent);color:#081027;font-weight:750;cursor:pointer}.btn:hover{filter:brightness(1.08)}.btn.small{padding:7px 10px;font-size:12px}.btn.ghost{background:#202b44;color:var(--text)}.btn.full{width:100%;margin-top:8px}form label{display:block;color:#cdd5e8;font-size:12px;margin-bottom:14px}input,textarea,select{display:block;width:100%;margin-top:7px;background:#0c1324;color:var(--text);border:1px solid var(--line);border-radius:9px;padding:10px 11px;outline:none}textarea{min-height:130px;resize:vertical}input:focus,textarea:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(124,156,255,.1)}.inline-form{display:flex;gap:7px;align-items:center;margin:0}.inline-form select{margin:0;min-width:130px;padding:7px}.activity{display:flex;flex-direction:column}.activity-row{display:flex;gap:12px;padding:12px 0;border-bottom:1px solid var(--line)}.activity-row:last-child{border-bottom:0}.activity-row p{margin:3px 0;color:#b8c2d8}.activity-row small{color:var(--muted)}.dot{width:8px;height:8px;border-radius:50%;background:var(--accent);margin-top:7px;flex:none}.ticket-list{display:grid;gap:14px}.toolbar{display:flex;justify-content:flex-end;margin:-4px 0 14px}.ticket-link{color:var(--text);font-weight:650}.ticket-link:hover,.back-link{color:var(--accent)}.back-link{display:inline-block;margin-bottom:14px}.description{white-space:pre-wrap}.comment-form.wide{max-width:900px}.ticket{border:1px solid var(--line);border-radius:14px;padding:18px;background:#0f1729}.ticket-top{display:flex;justify-content:space-between;gap:16px}.ticket p{color:#b9c3d8;margin:12px 0}.meta{display:flex;gap:22px;color:var(--muted);font-size:12px;margin-bottom:14px}.actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.comment-form{display:flex;gap:7px;flex:1;margin:0}.comment-form input{margin:0;min-width:220px}.alert{padding:11px 13px;border-radius:10px;margin-bottom:16px;border:1px solid var(--line)}.alert.danger{background:rgba(255,104,120,.1);color:#ffb5bd;border-color:rgba(255,104,120,.25)}.login-shell{min-height:100vh;display:grid;place-items:center;padding:20px}.login-card{width:min(430px,100%);background:rgba(17,24,42,.95);border:1px solid var(--line);border-radius:20px;padding:32px;box-shadow:0 30px 90px rgba(0,0,0,.35)}.login-card .brand{margin-bottom:34px}.login-card h1{font-size:32px}.login-note{color:var(--muted);font-size:11px;text-align:center;margin-top:22px}@media(max-width:900px){.grid.two,.stats{grid-template-columns:1fr}.topbar{padding:0 16px}.container{padding:24px 16px}.userbox>span{display:none}} </style>";}
}
