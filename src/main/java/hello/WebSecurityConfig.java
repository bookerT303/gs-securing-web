package hello;

import hello.security.AuthenticateUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private AuthenticateUserService userService;

    public WebSecurityConfig() {
        this.userService = new AuthenticateUserService();
    }

    @Autowired
    AuthenticationManagerBuilder authManagerBuilder;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        BasicAuthenticationFilter basicAuthenticationFilter = new BasicAuthenticationFilter(
                authManagerBuilder.getOrBuild(), new CustomBasicAuthenticationEntryPoint());
        http
                .authorizeRequests()
                .antMatchers("/", "/home", "/unauthorized", "/error").permitAll()
                .anyRequest().authenticated()
//                .and().addFilterAt(basicAuthenticationFilter, BasicAuthenticationFilter.class)
                .and().httpBasic()
//                    .authenticationEntryPoint((request, response, authException) -> response.getWriter().write("basic Custom Authentication Required"))
//                .and()
//                .exceptionHandling()
//                .authenticationEntryPoint((request, response, authException) -> response.getWriter().write("Custom Authentication Required"))
//                .accessDeniedHandler((request, response, accessDeniedException) -> {
//                            response.getWriter().write("Custom Denied");
//                        })
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
        auth.userDetailsService(userService);
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
class CustomBasicAuthenticationEntryPoint extends BasicAuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.addHeader("WWW-Authenticate", "Basic realm=\"" + getRealmName() + "\"");
        response.setStatus(401);
        response.sendRedirect("forward:/unauthorized");
//        response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
//                authException.getMessage());
//
    }
}
