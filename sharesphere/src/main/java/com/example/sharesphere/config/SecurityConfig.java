package com.example.sharesphere.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // Autowire by type; UserService is @Primary so it will be injected
    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder; // comes from PasswordConfig

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .csrf(csrf -> csrf.disable())
                .cors(cors -> {
                }) // CORS will be handled by your CorsConfig

                .authorizeHttpRequests(auth -> auth

                        // PUBLIC
                        .requestMatchers("/", "/login", "/register").permitAll()
                        .requestMatchers("/api/tools").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/tool/**").permitAll()

                        // PROTECTED
                        .requestMatchers(HttpMethod.POST, "/api/tool").authenticated()
                        .requestMatchers(HttpMethod.PUT, "/api/tool/**").authenticated()
                        .requestMatchers(HttpMethod.DELETE, "/api/tool/**").authenticated()

                        .anyRequest().permitAll()
                )

                // allow session-based login
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                )

                // ⭐ ENABLE HTTP BASIC (required for session creation)
                .httpBasic(Customizer.withDefaults())

                // ⭐ REMOVE formLogin disabling
                .formLogin(Customizer.withDefaults())

                // register provider
                .authenticationProvider(authenticationProvider());

        http.headers(headers -> headers.frameOptions(frame -> frame.disable()));

        return http.build();
    }
}
