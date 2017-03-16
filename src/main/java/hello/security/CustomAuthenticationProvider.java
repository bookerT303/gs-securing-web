package hello.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;

import static java.util.Arrays.asList;

@Component
public class CustomAuthenticationProvider
        implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {

        String name = authentication.getName();
        String password = authentication.getCredentials().toString();

        if ("NO-WAY".equalsIgnoreCase(name)) {
            throw new UsernameNotFoundException("Invalid User");
        }
        System.out.printf("User: %s, Password: %s", name, password);
        return new UsernamePasswordAuthenticationToken(
                name, password, asList(new GrantedAuthorityImpl("ROLE_USER")
        ));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(
                UsernamePasswordAuthenticationToken.class);
    }
}