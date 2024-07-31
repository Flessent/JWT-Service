package flexe.org.jwt.services.implementation;

import flexe.org.jwt.entities.AppRoles;
import flexe.org.jwt.entities.AppUser;
import flexe.org.jwt.repositories.AppRolesRepository;
import flexe.org.jwt.repositories.AppUserRepository;
import flexe.org.jwt.services.interfaces.AccountServices;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@AllArgsConstructor
@Service
@Transactional
public class AccountServicesImpl implements AccountServices {

    private AppUserRepository appUserRepository;
    private AppRolesRepository appRolesRepository;
    private PasswordEncoder passwordEncoder;

    @Override
    public AppUser addUser(AppUser user) {

        user.setPassword(passwordEncoder.encode(user.getPassword()));


        return this.appUserRepository.save(user);
    }

    @Override
    public AppRoles addRole(AppRoles role) {
        return this.appRolesRepository.save(role);
    }

    @Override
    public void addRoleToUser(String username, String roleNme) {
        AppUser user=this.appUserRepository.findByUsername(username);
        AppRoles role =this.appRolesRepository.findByRoleName(roleNme);


        user.getAppRoles().add(role);
        role.getAppUsers().add(user);

    }

    @Override
    public AppUser findUserByUsername(String username) {
        return this.appUserRepository.findByUsername(username);
    }

    @Override
    public List<AppUser> listAppUsers() {
        return this.appUserRepository.findAll();
    }

    @Override
    public String encodePassword(String password) {

        BCryptPasswordEncoder bCryptPasswordEncoder= new BCryptPasswordEncoder();

        return bCryptPasswordEncoder.encode(password);
    }

    @Override
    public List<AppRoles> listRoles() {
        return this.appRolesRepository.findAll();
    }

    @Override
    public void changePassword(String username, String oldPassword, String newPassword,String enterAgainNewPassword) {
        AppUser user=this.appUserRepository.findByUsername(username);
        if(user.getPassword().equals(oldPassword) && newPassword.equals(enterAgainNewPassword)){
            user.setPassword(passwordEncoder.encode(newPassword));
        }else System.err.println("Old password was incorrect");
    }
}
