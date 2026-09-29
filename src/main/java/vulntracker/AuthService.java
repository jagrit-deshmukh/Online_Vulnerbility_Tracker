package vulntracker;

import java.sql.SQLException;
import java.util.Optional;

public final class AuthService {
    private final UserDao users = new UserDao();
    public Optional<User> login(String username, String password) throws SQLException { return users.authenticate(username, password); }
}
