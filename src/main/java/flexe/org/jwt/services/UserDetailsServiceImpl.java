package flexe.org.jwt.services;

import flexe.org.jwt.entities.AppUser;
import flexe.org.jwt.services.interfaces.AccountServices;
import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;

/*
@AllArgsConstructor
@Service

public class UserDetailsServiceImpl implements UserDetailsService {
private AccountServices accountServices;
/*
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser user = accountServices.findUserByUsername(username);

        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        user.getAppRoles().forEach(appRole -> {
            grantedAuthorities.add(new SimpleGrantedAuthority(appRole.getRoleName()));
        });
        return new User(user.getUsername(), user.getPassword(), grantedAuthorities);
    }
}
*/