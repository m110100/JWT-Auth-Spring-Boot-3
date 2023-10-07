package io.bytecloud.auth.service;

import io.bytecloud.auth.model.Token;
import io.bytecloud.auth.repository.TokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class TokenService {
    private final TokenRepository tokenRepository;

    /**
     * Получает токен по его значению.
     *
     * @param token Значение токена.
     * @return Токен, если он найден, в противном случае возвращает пустой объект Optional.
     */
    public Optional<Token> getToken(String token) {
        return tokenRepository.findByToken(token);
    }

    /**
     * Получает список всех действительных токенов пользователя по его идентификатору.
     *
     * @param userId Идентификатор пользователя.
     * @return Список всех действительных токенов пользователя.
     */
    public List<Token> getAllValidTokens(Long userId) {
        return tokenRepository.findAllValidTokenByUser(userId);
    }

    /**
     * Сохраняет токен в базе данных.
     *
     * @param token Токен для сохранения.
     */
    public void saveToken(Token token) {
        tokenRepository.save(token);
    }

    /**
     * Сохраняет список токенов в базе данных.
     *
     * @param tokens Список токенов для сохранения.
     */
    public void saveAllTokens(List<Token> tokens) {
        tokenRepository.saveAll(tokens);
    }
}
