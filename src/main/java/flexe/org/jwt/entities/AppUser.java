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

//Users of my Application
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Data
@Table(name="Users")
public class AppUser implements Serializable {
    @Id
    @UuidGenerator
    @Column(name = "user_id")
    private UUID userId;
    private String username;
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)

    private String password;
    @ManyToMany(mappedBy = "appUsers", fetch = FetchType.EAGER)

    private Collection<AppRoles> appRoles = new ArrayList<>();
}
