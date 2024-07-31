package flexe.org.jwt;

import flexe.org.jwt.entities.AppRoles;
import flexe.org.jwt.entities.AppUser;
import flexe.org.jwt.services.interfaces.AccountServices;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.stream.Stream;

@SpringBootApplication
public class JwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner start(AccountServices accountServices){
		return args->{
			Stream.of("flexe","merkel","modestine","mueller")
					.forEach(name->{
						AppUser user=new AppUser();
						user.setUsername(name+"@gov.de");
						user.setPassword(name+"12345");

						accountServices.addUser(user);

			});
			Stream.of("USER","ADMIN","GUEST","CEO")
					.forEach(roleName->{
						AppRoles role=new AppRoles();
						role.setRoleName(roleName);
						role.setDescription("This role is for "+roleName);
						accountServices.addRole(role);
					});

			accountServices.addRoleToUser(accountServices.listAppUsers().get(0).getUsername(), accountServices.listRoles().get(0).getRoleName());
			accountServices.addRoleToUser(accountServices.listAppUsers().get(0).getUsername(), accountServices.listRoles().get(1).getRoleName());

			accountServices.addRoleToUser(accountServices.listAppUsers().get(1).getUsername(), accountServices.listRoles().get(1).getRoleName());
			accountServices.addRoleToUser(accountServices.listAppUsers().get(2).getUsername(), accountServices.listRoles().get(3).getRoleName());
			accountServices.addRoleToUser(accountServices.listAppUsers().get(3).getUsername(), accountServices.listRoles().get(2).getRoleName());
		};
	}


}
