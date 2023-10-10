package io.bytecloud.auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.bytecloud.auth.dto.request.AuthRequest;
import io.bytecloud.auth.dto.response.AuthResponse;
import io.bytecloud.auth.model.Token;
import io.bytecloud.auth.model.User;
import io.bytecloud.auth.model.enums.RoleType;
import io.bytecloud.auth.model.enums.TokenType;
import io.bytecloud.auth.security.UserDetailsImpl;
import io.bytecloud.auth.security.JwtAuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final PasswordEncoder passwordEncoder;
    private final JwtAuthenticationService jwtAuthenticationService;
    private final AuthenticationManager authenticationManager;

    private final TokenService tokenService;
    private final RoleService roleService;
    private final UserService userService;

    /**
     * Метод регистрации нового пользователя.
     *
     * @param request Запрос на регистрацию пользователя.
     */
    public User signUp(AuthRequest request) {
        User user = User.builder()
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .role(roleService.getRole(RoleType.USER))
                .build();

        return userService.saveUser(user);
    }

    /**
     * Метод входа пользователя.
     *
     * @param request Запрос на вход пользователя.
     * @return Ответ с авторизационными токенами (Access Token и Refresh Token).
     */
    public AuthResponse signIn(AuthRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.email(),
                        request.password()
                )
        );

        User user = userService.getUserByEmail(request.email());
        List<SimpleGrantedAuthority> authorities = roleService.getAuthorities(user.getId());

        UserDetailsImpl userDetails = new UserDetailsImpl(user.getEmail(), user.getPassword(), authorities);

        String accessToken = jwtAuthenticationService.generateAccessToken(userDetails);
        String refreshToken = jwtAuthenticationService.generateRefreshToken(userDetails);

        revokeAllUserTokens(user);
        saveUserToken(user, accessToken);

        return new AuthResponse(accessToken, refreshToken);
    }

    // TODO Добавить метод для отзыва токенов через endpoint

    /**
     * Метод обновления Access Token на основе Refresh Token.
     *
     * @param request  Запрос, содержащий Refresh Token.
     * @param response Ответ, в который будет записан новый Access Token.
     * @throws IOException Если произойдут ошибки при записи в ответ.
     */
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String email;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) return;

        refreshToken = authHeader.substring(7);
        email = jwtAuthenticationService.extractUsername(refreshToken);

        if (email != null) {
            User user = userService.getUserByEmail(email);

            List<SimpleGrantedAuthority> authorities = roleService.getAuthorities(user.getId());

            UserDetailsImpl userDetails = new UserDetailsImpl(user.getEmail(), user.getPassword(), authorities);

            if (jwtAuthenticationService.isTokenValid(refreshToken, userDetails)) {
                String accessToken = jwtAuthenticationService.generateAccessToken(userDetails);

                revokeAllUserTokens(user);
                saveUserToken(user, accessToken);

                AuthResponse authResponse = new AuthResponse(accessToken, refreshToken);

                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }

    /**
     * Сохраняет токен пользователя в базе данных.
     *
     * @param user Пользователь, которому принадлежит токен.
     * @param accessToken Access Token для сохранения.
     */
    private void saveUserToken(User user, String accessToken) {
        Token token = Token.builder()
                .user(user)
                .token(accessToken)
                .type(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();

        tokenService.saveToken(token);
    }

    /**
     * Отзывает все токены пользователя и сохраняет изменения в базе данных.
     *
     * @param user Пользователь, чьи токены отзываются.
     */
    private void revokeAllUserTokens(User user) {
        List<Token> tokens = tokenService.getAllValidTokens(user.getId());

        if (tokens.isEmpty()) return;

        tokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });

        tokenService.saveAllTokens(tokens);
    }
}
