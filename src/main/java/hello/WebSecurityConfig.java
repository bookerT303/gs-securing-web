package hello;

import hello.security.AuthenticateUserService;
import hello.security.Role;
import hello.security.UserData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static java.util.Arrays.asList;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private AuthenticateUserService userService;

    private AuthenticationProvider authProvider;


    public WebSecurityConfig() {
        this.authProvider = new CustomAuthenticationProvider();
        this.userService = new AuthenticateUserService();
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
                .antMatchers("/", "/home", "/unauthorized", "/error").permitAll()
                .anyRequest().authenticated()
                .and()
//                .addFilterAt(basicAuthenticationFilter, BasicAuthenticationFilter.class)
                .httpBasic()
                .authenticationEntryPoint((request, response, authException) ->
                        response.sendError(401, "Call Bob")
                )
                .and()
                .exceptionHandling()
                .authenticationEntryPoint((request, response, authException) -> {
                            response.addHeader("WWW-Authenticate", "Basic realm=\"" + authenticationEntryPoint.getRealmName() + "\"");
                            response.sendError(401, "Please Login");
                        }
                )
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    response.getWriter().write("Custom Denied");
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

//    private void handleAuthenticationException(BasicAuthenticationEntryPoint authenticationEntryPoint, HttpServletResponse response, AuthenticationException authException) throws IOException {
//        if (authException instanceof BadCredentialsException) {
//            response.sendError(401, "Call Bob");
//        } else {
//            response.addHeader("WWW-Authenticate", "Basic realm=\"" + authenticationEntryPoint.getRealmName() + "\"");
//            response.sendError(401, "Please Login");
//        }
//    }
//
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authProvider);
//        auth.userDetailsService(userService);
    }
}

//class StatelessLoginFilter extends AbstractAuthenticationProcessingFilter {
//
//    @Override
//    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
//        return null;
//    }
//
//    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
//                                              AuthenticationException failed) throws IOException, ServletException {
//        SecurityContextHolder.clearContext();
//
//        if (logger.isDebugEnabled()) {
//            logger.debug("Authentication request failed: " + failed.toString());
//            logger.debug("Updated SecurityContextHolder to contain null Authentication");
//            logger.debug("Delegating to authentication failure handler " + failureHandler);
//        }
//
//        //        response.setCharacterEncoding("UTF-8");
//        //        response.getWriter().write(jsonService.toString(jsonService.getResponse(false, "Не удалось авторизоваться", "401")));
//
//        rememberMeServices.loginFail(request, response);
//        failureHandler.onAuthenticationFailure(request, response, failed);
//
//    }
//}
//class CustomBasicAuthenticationEntryPoint extends BasicAuthenticationEntryPoint {
//    @Override
//    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
////        response.addHeader("WWW-Authenticate", "Basic realm=\"" + getRealmName() + "\"");
////        response.setStatus(401);
//        response.sendRedirect("forward:/unauthorized");
////        response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
////                authException.getMessage());
////
//    }
//}
class CustomAuthenticationProvider
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