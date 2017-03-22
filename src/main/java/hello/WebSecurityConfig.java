package hello;

import hello.security.AuthenticateUserService;
import hello.security.Role;
import hello.security.UserData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import sun.plugin.liveconnect.SecurityContextHelper;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private AuthenticateUserService userService;

    private AuthenticationProvider authProvider;

    private AccessDecisionManager accessDecisionManager;

    public WebSecurityConfig() {
        this.authProvider = new CustomAuthenticationProvider();
        this.userService = new AuthenticateUserService();
        this.accessDecisionManager = new CustomerAccessDecisionManager();
    }

    @Autowired
    AuthenticationManagerBuilder authManagerBuilder;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        BasicAuthenticationEntryPoint authenticationEntryPoint = new BasicAuthenticationEntryPoint();
        BasicAuthenticationFilter basicAuthenticationFilter = new BasicAuthenticationFilter(
                authManagerBuilder.getOrBuild(), authenticationEntryPoint);
        http
                .authorizeRequests()
                .antMatchers("/", "/home", "/unauthorized", "/error", "/favicon.ico").permitAll()
                .accessDecisionManager(accessDecisionManager)
                .anyRequest().authenticated()
                .and()
//                .addFilterAt(basicAuthenticationFilter, BasicAuthenticationFilter.class)
                .httpBasic()
                .authenticationEntryPoint((request, response, authException) ->
                        response.sendError(401, "Call Bob to become a user")
                )
                .and()
                .exceptionHandling()
                .authenticationEntryPoint((request, response, authException) -> {
                            response.addHeader("WWW-Authenticate", "Basic realm=\"" + authenticationEntryPoint.getRealmName() + "\"");
                            response.sendError(401, "Please Login");
                        }
                )
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    response.sendError(403, "Call Bob to get access");
                })
//                .and()
//            .formLogin()
//                .loginPage("/login")
//                .permitAll()
//                .failureUrl("/unauthorized")
//                .and()
//                .logout()
//                .logoutUrl("/logout")
//                .clearAuthentication(true)
//                .logoutSuccessUrl("/home")
//                .permitAll()
        ;
    }
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authProvider);
//        auth.userDetailsService(userService);
    }
}

class CustomAuthenticationProvider
        implements AuthenticationProvider {
    private final List<UserData> users;

    public CustomAuthenticationProvider() {
        users = asList(
                new UserData("noAccess", "password", true, emptyList()),
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
//                .orElseThrow(() -> new BadCredentialsException("Please Login:"));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(
                UsernamePasswordAuthenticationToken.class);
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

}

class CustomerAccessDecisionManager implements AccessDecisionManager {

    @Override
    public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes) throws AccessDeniedException, InsufficientAuthenticationException {
        if (object instanceof FilterInvocation) {
            FilterInvocation invocation = (FilterInvocation) object;
            boolean bail = false;
            if (bail) {
                throw new AccessDeniedException("Not allowed");
            }
            Optional<ConfigAttribute> authenticated = configAttributes.stream()
                    .filter(attribute -> "authenticated".equals(attribute.toString()))
                    .findAny();
            if (authenticated.isPresent()) {
                // TODO we need to check the authentication
                boolean isLoggedIn = authentication.isAuthenticated();
                Optional<? extends GrantedAuthority> hasRole = authentication.getAuthorities().stream()
                        .filter(role -> role.getAuthority().equalsIgnoreCase("role_user"))
                        .findAny();
                if (hasRole.isPresent() == false) {
                    throw new AccessDeniedException("Not allowed");
                }
            }
        }
        return;
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }
}