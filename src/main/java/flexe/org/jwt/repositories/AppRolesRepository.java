package flexe.org.jwt.repositories;

import flexe.org.jwt.entities.AppRoles;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface AppRolesRepository extends JpaRepository<AppRoles, UUID> {
    AppRoles findByRoleName(String roleName);
}
