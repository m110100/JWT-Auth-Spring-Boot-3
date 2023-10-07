package io.bytecloud.auth.security;

import io.bytecloud.auth.model.Token;
import io.bytecloud.auth.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogoutHandlerImpl implements LogoutHandler {
    private final TokenService tokenService;

    /**
     * Обрабатывает выход пользователя из системы.
     *
     * @param request Запрос пользователя.
     * @param response Ответ, который будет отправлен пользователю.
     * @param authentication Аутентификация пользователя, который выходит из системы.
     */
    @Override
    public void logout(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String jwt;

        // Проверка наличия и формата JWT токена в заголовке авторизации
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }

        // Извлечение JWT из заголовка
        jwt = authHeader.substring(7);

        // Получение информации о хранящемся токене в базе данных
        Token storedToken = tokenService.getToken(jwt)
                .orElse(null);

        // Если токен найден
        if (storedToken != null) {
            // Установка токена как просроченного и отозванного
            storedToken.setExpired(true);
            storedToken.setRevoked(true);

            // Сохранение изменений в базе данных
            tokenService.saveToken(storedToken);

            // Очистка контекста безопасности
            SecurityContextHolder.clearContext();
        }
    }
}
