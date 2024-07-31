package flexe.org.jwt.security;

import flexe.org.jwt.entities.AppUser;
import flexe.org.jwt.security.filters.JWTAuthenticationFilter;
import flexe.org.jwt.security.filters.JWTAuthorizationFilter;
import flexe.org.jwt.services.interfaces.AccountServices;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.ArrayList;
import java.util.Collection;


@EnableWebSecurity
@Configuration
@AllArgsConstructor
public class SecurityConfig {

private AccountServices accountServices;



    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                AppUser user = accountServices.findUserByUsername(username);

                Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
                user.getAppRoles().forEach(appRole -> {
                    grantedAuthorities.add(new SimpleGrantedAuthority(appRole.getRoleName()));
                });
                return new User(user.getUsername(), user.getPassword(), grantedAuthorities);
            }
        };
    }


// Statefull authentication : Managed through session-Id and handled on server-side
  /*  @Bean
    public SecurityFilterChain configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .authorizeHttpRequests(authz -> authz
                        .anyRequest().authenticated()
                )
                .formLogin(withDefaults());

        return httpSecurity.build();
    }
*/

// Stateless authentication through JWT and handled on client-side

    @Bean
    public SecurityFilterChain configure(HttpSecurity httpSecurity) throws Exception {


        httpSecurity.csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authz -> authz
                        // erste Lösung für Authorization auf eine Rest-Method nach Rechten
                        //.requestMatchers("/admin/**").hasAuthority("ADMIN")
                        //.requestMatchers("/user/**").hasAuthority("USER")
                        .requestMatchers("/refreshToken/**","/login/**").permitAll()
                        .anyRequest().authenticated())

                          .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        httpSecurity.addFilter(new JWTAuthenticationFilter(authenticationManager(httpSecurity.getSharedObject(AuthenticationConfiguration.class))));
        httpSecurity.addFilterBefore(new JWTAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);


        return  httpSecurity.build();
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

}
