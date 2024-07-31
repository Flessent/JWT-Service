package flexe.org.jwt.security.filters;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import flexe.org.jwt.security.JWTUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

// for managing the authorization : who can do what
public class JWTAuthorizationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if(request.getServletPath().equals(JWTUtils.REFRESH_TOKEN_PATH)){
            filterChain.doFilter(request,response);
        } else {
            String jwtAuthorizationToken=request.getHeader(JWTUtils.AUTHORIZATION_HEADER);
            if(jwtAuthorizationToken!=null && jwtAuthorizationToken.startsWith(JWTUtils.JWT_PREFIX_TOKEN)){
                try {
                    String generatedJwtToken=jwtAuthorizationToken.substring(JWTUtils.JWT_PREFIX_TOKEN.length());
                    Algorithm algorithm=Algorithm.HMAC256(JWTUtils.SECRET);
                    JWTVerifier jwtTokenVerifier= JWT.require(algorithm).build();
                    DecodedJWT decodedJWT= jwtTokenVerifier.verify(generatedJwtToken);
                    // get claims
                    String username=decodedJWT.getSubject();
                    String [] roles=decodedJWT.getClaim("roles").asArray(String.class);

                    Collection<GrantedAuthority> authorities= new ArrayList<>();
                    for(String r:roles){
                        authorities.add(new SimpleGrantedAuthority(r));
                        System.err.println("Roles :"+r);
                    }
                    UsernamePasswordAuthenticationToken authenticationToken=
                            new UsernamePasswordAuthenticationToken(username,null,authorities );// null here represents the password. We don't need to provide the password anymore.
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    filterChain.doFilter(request,response); // go to the next Filter

                }catch (Exception e){
                    response.setHeader("error-message",e.getMessage());
                    response.sendError(HttpServletResponse.SC_FORBIDDEN);
                }


            }  else{
                filterChain.doFilter(request,response); // go to the next Filter
            }
        }





    }
}
