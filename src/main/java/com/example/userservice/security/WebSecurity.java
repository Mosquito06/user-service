package com.example.userservice.security;

import com.example.userservice.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;

@Configuration
@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter
{

    private UserService userService;
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private Environment env;

    @Autowired
    public WebSecurity(Environment env, UserService userService, BCryptPasswordEncoder bCryptPasswordEncoder)
    {
        this.env = env;
        this.userService = userService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        http.csrf().disable();
        //http.authorizeRequests().antMatchers("/users/**").permitAll();

        http.authorizeHttpRequests( authorizeRequest ->
        {
            try
            {
                authorizeRequest.antMatchers("/actuator/**")
                                .permitAll()
                                .mvcMatchers("/")
                                .access(hasIpAddress("192.168.222.92"))
                                .and()
                                .addFilter(getAuthenticationFilter());
            }
            catch (Exception e)
            {
                throw new RuntimeException(e);
            }
        });
        http.headers().frameOptions().disable();
    }

    private static AuthorizationManager<RequestAuthorizationContext> hasIpAddress(String ipAddress)
    {
        IpAddressMatcher ipAddressMatcher = new IpAddressMatcher(ipAddress);

        return (authentication, context) ->
        {
            HttpServletRequest request = context.getRequest();
            return new AuthorizationDecision(ipAddressMatcher.matches(request));
        };
    }

    private AuthenticationFilter getAuthenticationFilter() throws Exception
    {
        AuthenticationFilter authenticationFilter = new AuthenticationFilter(authenticationManager(), userService, env);
        // authenticationFilter.setAuthenticationManager( authenticationManager() );

        return authenticationFilter;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception
    {
        auth.userDetailsService(userService).passwordEncoder(bCryptPasswordEncoder);
    }
}