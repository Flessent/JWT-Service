package flexe.org.jwt.services.interfaces;

import flexe.org.jwt.entities.AppRoles;
import flexe.org.jwt.entities.AppUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;


public interface AccountServices {
   AppUser addUser(AppUser user);
AppRoles addRole(AppRoles role);
void addRoleToUser(String username,String role);
AppUser findUserByUsername(String username);
List<AppUser> listAppUsers();
String encodePassword(String password);

List<AppRoles> listRoles();


void  changePassword(String username,String oldPassword,String newPassword, String enterAgainNewPassword);
}
