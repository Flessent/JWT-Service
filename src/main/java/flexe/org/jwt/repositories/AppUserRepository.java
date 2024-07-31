package flexe.org.jwt.repositories;

import flexe.org.jwt.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface AppUserRepository extends JpaRepository<AppUser, UUID> {
    AppUser findByUsername(String username);
}
