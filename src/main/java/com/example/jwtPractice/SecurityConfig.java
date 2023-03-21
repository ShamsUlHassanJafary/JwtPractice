package com.example.jwtPractice;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

//    @Bean
//    public UserDetailsService userDetailsService() {
//        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
//        manager.createUser(User.withUsername("user")
//                .password("12345678")
//                .roles("USER")
//                .build());
//        manager.createUser(User.withUsername("admin")
//                .password("12345678")
//                .roles("USER", "ADMIN")
//                .build());
//        return manager;
//    }

//    @Bean
//    public UserDetailsService userDetailsService() {
//        var uds = new InMemoryUserDetailsManager();
//
//        var u1 = User.withUsername("bill")
//                .password("12345")
//                .roles("ADMIN")
//                .authorities("read")
//                .build();
//
//        uds.createUser(u1);
//
//        return uds;
//    }

    @Bean
    public UserDetailsService userDetailsService() {
        var uds = new InMemoryUserDetailsManager();

        var u1 = User.withUsername("bill")
                .password("12345")
                .roles("ADMIN")
                .authorities("read")
                .build();

        var u2 = User.withUsername("ted")
                .password("54321")
                .roles("USER")
                .authorities("read")
                .build();

        uds.createUser(u1);
        uds.createUser(u2);

        return uds;
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//
//        http.csrf().disable()
//                .authorizeRequests()
//                .antMatchers("/authenticate").permitAll()
//                .antMatchers("/admin/**").hasRole("ADMIN") // allow access to /admin/** endpoints only for users with ADMIN role
//                .anyRequest().authenticated();

        http.csrf().disable()
                .authorizeRequests()
                .mvcMatchers("/authenticate").permitAll()
//                .antMatchers("/admin/**").hasRole("ADMIN")
//                .antMatchers("/admin/greet/**").authenticated() // allow access to /admin/greet/** endpoints for all authenticated users
                .anyRequest().authenticated();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService());
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
