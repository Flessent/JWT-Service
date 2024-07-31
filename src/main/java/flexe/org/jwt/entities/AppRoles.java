package flexe.org.jwt.entities;


import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.UuidGenerator;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.UUID;

//Roles of users of my Application
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Data
@Table(name="Roles")
public class AppRoles implements Serializable {
    @Id
    @UuidGenerator
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @Column(name = "role_id")
    private UUID roleId;
    private String roleName;
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String description;


    @ManyToMany
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "user_id"))

    private Collection<AppUser> appUsers = new ArrayList<>();
}
