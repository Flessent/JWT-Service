package flexe.org.jwt.restcontroller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import flexe.org.jwt.entities.AppRoles;
import flexe.org.jwt.entities.AppUser;
import flexe.org.jwt.security.JWTUtils;
import flexe.org.jwt.services.interfaces.AccountServices;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@EnableMethodSecurity(securedEnabled = true,prePostEnabled = true)
public class AccountRestController {

    @Autowired
    private AccountServices accountServices;

    @GetMapping(path = "/getUser/{username}")
    /*
    * @PreAuthorize verifies the  given expression after the execution of the method and could alter the result.
    *   @PostAuthorize checks the given expression before entering the method
    * */
    @PostAuthorize("hasAuthority('USER') or hasAuthority('ADMIN') or hasAuthority('CEO')")
public AppUser getUserByUsername(@PathVariable String username){
  return this.accountServices.findUserByUsername(username);
}

     // return authenticated User
    //@PostAuthorize("hasAuthority('ADMIN') or hasAuthority('CEO')")
    @GetMapping(path = "/profile")
    public AppUser profile(Principal principal){
        return this.accountServices.findUserByUsername(principal.getName());
    }

    @GetMapping(path = "/user/getAllUsers")
    @PostAuthorize("hasAuthority('USER') or hasAuthority('ADMIN')")
    public List<AppUser> getListAllUsers(){
        return this.accountServices.listAppUsers();
    }
    @PostAuthorize("hasAuthority('ADMIN') or hasAuthority('CEO')")
    @PostMapping(path = "/admin/addNewUser")
    public AppUser addNewAppUser(@RequestBody  AppUser user){
        return this.accountServices.addUser(user);
    }
    @PostAuthorize("hasAuthority('ADMIN')")
    @PostMapping(path = "/admin/addNewRole")
    public AppRoles addNewAppRole(@RequestBody  AppRoles role){
        return this.accountServices.addRole(role);
    }
    @PostAuthorize("hasAuthority('ADMIN') or hasAuthority('CEO')")
    @PostMapping(path = "/admin/addRoleToUser")
    public void addRoleToUser(@RequestBody  RoleUserForm  roleUserForm){
         this.accountServices.addRoleToUser(roleUserForm.getUsername(),roleUserForm.getRoleName());
    }


    @GetMapping("/refreshToken")
    @PostAuthorize("hasAuthority('ADMIN') or hasAuthority('CEO')")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String jwtAuthorizationToken=request.getHeader(JWTUtils.AUTHORIZATION_HEADER);
        if(jwtAuthorizationToken!=null && jwtAuthorizationToken.startsWith(JWTUtils.JWT_PREFIX_TOKEN)){
            try {
                String refreshToken=jwtAuthorizationToken.substring(JWTUtils.JWT_PREFIX_TOKEN.length());
                Algorithm algorithm=Algorithm.HMAC256(JWTUtils.SECRET);
                JWTVerifier jwtTokenVerifier= JWT.require(algorithm).build();
                DecodedJWT decodedJWT= jwtTokenVerifier.verify(refreshToken);
                // get claims
                String username=decodedJWT.getSubject();
                AppUser appUser=accountServices.findUserByUsername(username); // load the user again if smth for example right changed
                // generate a new access token
                String jwtAccessToken= JWT.create()
                        //Register claims
                        .withSubject(appUser.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis()+ JWTUtils.EXPIRE_ACCESS_TOKEN))  // Token will expire in EXPIRE_ACCESS_TOKEN  min
                        .withIssuer(request.getRequestURL().toString())
                        //private claims
                        .withClaim("roles",appUser.getAppRoles().stream().map(role->role.getRoleName()).collect(Collectors.toList()))
                        //signature
                        .sign(algorithm);
                Map<String, String> idToken = new HashMap<>();

                idToken.put("access-token", jwtAccessToken);
                idToken.put("refresh-token", refreshToken);
                response.setContentType("application/json"); // indicate that the response body contains json information
                new ObjectMapper().writeValue(response.getOutputStream(),idToken); // write the jwt  token(json format) in the response body


            }catch (Exception e){
                throw e;
            }


        }else {
            throw new RuntimeException("Refresh Token required");
        }
    }



}
// class for Post API Method (add a new Role to a User)
@Data
class  RoleUserForm{
    private String username;
    private String roleName;
}