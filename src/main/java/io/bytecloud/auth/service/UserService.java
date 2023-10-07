package io.bytecloud.auth.service;

import io.bytecloud.auth.exception.UserNotFoundException;
import io.bytecloud.auth.model.User;
import io.bytecloud.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    /**
     * Получает пользователя по его адресу электронной почты.
     *
     * @param email Адрес электронной почты пользователя.
     * @return Пользователь, если он найден, в противном случае выбрасывает исключение.
     * @throws UserNotFoundException Исключение, возникающее при отсутствии пользователя с указанным адресом электронной почты.
     */
    public User getUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
    }

    /**
     * Сохраняет пользователя в базе данных.
     *
     * @param user Пользователь для сохранения.
     * @return Пользователь, если успешно сохранен
     */
    public User saveUser(User user) {
        return userRepository.save(user);
    }
}
