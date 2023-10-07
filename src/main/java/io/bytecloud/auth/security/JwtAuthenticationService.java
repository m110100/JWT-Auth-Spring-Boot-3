package io.bytecloud.auth.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtAuthenticationService {
    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    @Value("${application.security.jwt.expiration}")
    private long accessExpiration;

    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;

    /**
     * Извлекает email из JWT токена.
     *
     * @param token Токен JWT, из которого можно извлечь адрес электронной почты.
     * @return Адрес электронной почты, извлеченный из токена JWT.
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Извлекает конкретный claims из JWT, применяя функцию claimResolver.
     *
     * @param token Токен JWT, из которого извлекается claims.
     * @param claimsResolver Функция, которая извлекает claims из JWT токена.
     * @return Извлеченный claims типа T.
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);

        return claimsResolver.apply(claims);
    }

    /**
     * Генерирует токен доступа (Access Token) на основе данных о пользователе (UserDetails).
     *
     * @param userDetails Информация о пользователе, на основе которой будет сгенерирован токен доступа.
     * @return Сгенерированный токен доступа.
     */
    public String generateAccessToken(UserDetails userDetails) {
        return generateAccessToken(new HashMap<>(), userDetails);
    }

    /**
     * Генерирует токен доступа (Access Token) на основе информации о пользователе (UserDetails) и дополнительных
     * пользовательских данных (extraClaims).
     *
     * @param extraClaims Дополнительные пользовательские данные, которые могут быть включены в токен.
     * @param userDetails Информация о пользователе, на основе которой будет сгенерирован токен доступа.
     * @return Сгенерированный токен доступа.
     */
    public String generateAccessToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return buildToken(extraClaims, userDetails, accessExpiration);
    }

    /**
     * Генерирует токен обновления (Refresh Token) на основе информации о пользователе (UserDetails).
     *
     * @param userDetails Информация о пользователе, на основе которой будет сгенерирован токен обновления.
     * @return Сгенерированный токен обновления.
     */
    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }

    /**
     * Внутренний метод для построения токена на основе информации о пользователе и параметров токена.
     *
     * @param extraClaims  Дополнительные пользовательские данные, которые могут быть включены в токен.
     * @param userDetails  Информация о пользователе, на основе которой будет сгенерирован токен.
     * @param expiration   Срок действия токена (в миллисекундах) от текущего времени.
     * @return Сгенерированный токен.
     */
    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Проверяет, действителен ли переданный токен для указанных пользовательских данных.
     *
     * @param token        Токен, который требуется проверить.
     * @param userDetails  Информация о пользователе, с которой сравнивается токен.
     * @return true, если токен действителен для указанных пользовательских данных, иначе false.
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);

        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    /**
     * Проверяет, истек ли срок действия переданного токена (Token).
     *
     * @param token Токен, срок действия которого проверяется.
     * @return true, если срок действия токена истек, иначе false.
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Извлекает дату истечения срока действия токена из переданного токена.
     *
     * @param token Токен, из которого извлекается дата истечения срока действия.
     * @return Дата истечения срока действия токена.
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Извлекает все данные (Claims) из переданного токена.
     *
     * @param token Токен, из которого извлекаются данные (Claims).
     * @return Объект Claims, содержащий все данные из токена.
     */
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Получает ключ для подписи токенов на основе секретного ключа.
     *
     * @return Ключ для подписи токенов.
     */
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
