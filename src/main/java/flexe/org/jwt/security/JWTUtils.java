package flexe.org.jwt.security;

public class JWTUtils {

    public static  final String SECRET="myBestSecret";


    public static  final String AUTHORIZATION_HEADER="Authorization";
    public static  final long EXPIRE_ACCESS_TOKEN=2*60*1000; // 2 minutes
    public static  final long EXPIRE_REFRESH_TOKEN=60*60*1000; // 1 hour
    public static  final String USERNAME_PARAM="username";
    public static  final String PASSWORD_PARAM="password";
    public static  final  String JWT_PREFIX_TOKEN="Bearer ";
    public  static  final  String REFRESH_TOKEN_PATH="/refreshToken";

}
