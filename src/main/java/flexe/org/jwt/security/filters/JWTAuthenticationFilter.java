package flexe.org.jwt.security.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import flexe.org.jwt.security.JWTUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

// for managing the login
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username=request.getParameter(JWTUtils.USERNAME_PARAM);
        String password=request.getParameter(JWTUtils.PASSWORD_PARAM);
        System.out.println("Username : "+username+" Password :"+password);
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(username,password);

        return authenticationManager.authenticate(usernamePasswordAuthenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        User user = (User)authResult.getPrincipal();
        Algorithm algorithm= Algorithm.HMAC256(JWTUtils.SECRET); /*private key.Here we are using a symetric algo for hashing i.e
 the same private key is used for encode and decide the message*/
        String jwtAccessToken= JWT.create()
                //Register claims
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+ JWTUtils.EXPIRE_ACCESS_TOKEN))  // Access Token will expire in 2 min
                .withIssuer(request.getRequestURL().toString())
                //private claims
                .withClaim("roles",user.getAuthorities().stream().map(ga->ga.getAuthority()).collect(Collectors.toList()))
                //signature
                .sign(algorithm);

// Refresh Token is used when the AccessToken expires. A new AccessToken is again created for extending your session
        //We don't need anymore the roles since we have the user presents his username and JWT trusts him and send a new AccessToken
        String jwtRefreshToken= JWT.create()
                //Register claims
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+JWTUtils.EXPIRE_REFRESH_TOKEN))  // RefreshToken will expire in 15 min
                .withIssuer(request.getRequestURL().toString())
                //signature
                .sign(algorithm);
        Map<String, String> idToken = new HashMap<>();

        idToken.put("access-token", jwtAccessToken);
        idToken.put("refresh-token", jwtRefreshToken);
response.setContentType("application/json"); // indicate that the response body contains json information
 new ObjectMapper().writeValue(response.getOutputStream(),idToken); // write the jwt  token(json format) in the response body


    }
}
