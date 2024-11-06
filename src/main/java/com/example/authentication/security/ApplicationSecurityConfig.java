package com.example.authentication.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
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
                        .anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults());

        return http.build();
    }


    @Bean
    public UserDetailsService userDetailsService(){
        User.UserBuilder user = User.builder()
                .username("prem")
                .password(passwordEncoder.encode("prem"))
                .roles(ApplicationUserRole.STUDENT.name());

        User.UserBuilder user1 = User.builder()
                .username("kamal")
                .password(passwordEncoder.encode("kamal"))
                .roles(ApplicationUserRole.ADMINTRAINEE.name());

        User.UserBuilder user2 = User.builder()
                .username("osipalli")
                .password(passwordEncoder.encode("osipalli"))
                .roles(ApplicationUserRole.ADMIN.name());


        return new InMemoryUserDetailsManager(user.build(),user1.build(), user2.build());
    }

}
