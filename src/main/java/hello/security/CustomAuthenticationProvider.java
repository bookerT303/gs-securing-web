package hello.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.util.Arrays.asList;

@Component
public class CustomAuthenticationProvider
        implements AuthenticationProvider {
    private final List<UserData> users;

    public CustomAuthenticationProvider() {
        users = asList(
                new UserData("user", "password", true, asList(new Role("ROLE_USER"))),
                new UserData("admin", "admin", true, asList(
                        new Role("ROLE_USER"),
                        new Role("ROLE_ADMIN")))
        );
    }

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {

        String name = authentication.getName();
        String password = authentication.getCredentials().toString();

        // WARNING... UserDetailsService returns the expected password and Spring will
        // validate that the user did login with the correct password....
        // HOWEVER the authenticationProvider is expected to have validated the password and the returned
        // password is really just informational...
        return users.stream()
                .filter(entry -> entry.getUsername().equals(name) && entry.getPassword().equals(password))
                .findFirst()
                .map(userData -> new UsernamePasswordAuthenticationToken(
                    userData.getUsername(), userData.getPassword(),
                    userData.getRoles().stream()
                        .map(role -> new GrantedAuthorityImpl(role.getRole()))
                        .collect(Collectors.toList())))
                .orElse(null);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(
                UsernamePasswordAuthenticationToken.class);
    }
}