package com.example.authentication.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;
import static com.example.authentication.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig {
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder){
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // Ensure CSRF is disabled if you don't need it
                .authorizeRequests(authorize -> authorize
                        .requestMatchers("/", "/index.html", "/css/*", "/js/*").permitAll()
                        .requestMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())
//                        .requestMatchers("/management/api/**").hasAnyRole(ADMIN.name(),ADMINTRAINEE.name())
//                        .requestMatchers(HttpMethod.DELETE,"/management/api/**").hasAnyAuthority(COURSE_WRITE.getPermission())
//                        .requestMatchers(HttpMethod.POST,"/management/api/**").hasAnyAuthority(COURSE_WRITE.getPermission())
//                        .requestMatchers(HttpMethod.PUT,"/management/api/**").hasAnyAuthority(COURSE_WRITE.getPermission())
//                        .requestMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(),ADMINTRAINEE.name())
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login")
                        .permitAll()
                        .defaultSuccessUrl("/courses", true)
                                .passwordParameter("password")
                                .usernameParameter("username")
                        )
                .rememberMe(remember -> remember
                        .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
                        .key("somethingverysecured")
                                .rememberMeParameter("remember-me")
                        )
                .logout(logout->logout
                        .logoutUrl("/logout")
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                        .clearAuthentication(true)
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID","remember-me")
                        .logoutSuccessUrl("/login"));

        return http.build();
    }


    @Bean
    public UserDetailsService userDetailsService(){
        User.UserBuilder user = User.builder()
                .username("prem")
                .password(passwordEncoder.encode("prem"))
//                .roles(ApplicationUserRole.STUDENT.name())
                .authorities(STUDENT.getGrantedAuthorities())
                ;

        User.UserBuilder user1 = User.builder()
                .username("kamal")
                .password(passwordEncoder.encode("kamal"))
//                .roles(ApplicationUserRole.ADMINTRAINEE.name())
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                ;

        User.UserBuilder user2 = User.builder()
                .username("osipalli")
                .password(passwordEncoder.encode("osipalli"))
//                .roles(ADMIN.name())
                .authorities(ADMIN.getGrantedAuthorities())
                ;


        return new InMemoryUserDetailsManager(user.build(),user1.build(), user2.build());
    }

}
