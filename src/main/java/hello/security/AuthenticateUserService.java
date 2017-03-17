package hello.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.List;
import java.util.stream.Collectors;

import static java.util.Arrays.asList;

public class AuthenticateUserService implements UserDetailsService {
    private final List<UserData> users;

    public AuthenticateUserService() {
        users = asList(
                new UserData("user", "password", true, asList(new Role("ROLE_USER"))),
                new UserData("admin", "admin", true, asList(
                        new Role("ROLE_USER"),
                        new Role("ROLE_ADMIN")))
        );
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // TODO : we should just get the UserData information from the database
        UserData userData = users.stream()
                .filter(entry -> entry.getUsername().equals(username))
                .findFirst().orElseThrow(() -> new UsernameNotFoundException("Unknown User " + username));

        return new User(userData.getUsername(), userData.getPassword(),
                userData.getRoles().stream()
                        .map(role -> new GrantedAuthorityImpl(role.getRole()))
                        .collect(Collectors.toList()));
    }
}

class GrantedAuthorityImpl implements GrantedAuthority {
    private String role;

    public GrantedAuthorityImpl(String role) {
        this.role = role;
    }

    @Override
    public String getAuthority() {
        return role;
    }
}
