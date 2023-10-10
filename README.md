# Настройка проекта

Файл `application.yaml` используется для настройки вашего приложения Spring. Прежде чем запустить приложение, вам потребуется внести изменения в него, чтобы адаптировать его к вашей среде и потребностям. Важно заменить значения `username`, `password` и `ddl-auto` на свои настройки.

## Замена значений в application.yaml

1. Откройте файл `application.yaml` по пути `src/main/resources/application.yaml` в проекте.
2. Найдите следующую секцию, содержащую настройки для базы данных. Она выглядит следующим образом:

   ```yaml
   spring:
     datasource:
       username: имя_пользователя
       password: пароль
     jpa:
       hibernate:
         ddl-auto: значение

## Запуск приложения
Чтобы начать работу с этим проектом, необходимо установить на компьютере следующее:

* JDK 17+
* Maven 3+
* PostgreSQL 14+

Чтобы запустить приложение необходимо выполнить следующее:
* Склонируйте проект `git clone https://github.com/m110100/JWT-Auth-Spring-Boot-3.git`
* Создайте базу данных `jwt` в СУБД PostgreSQL, а так же схему `jwt_sch`
* Соберите проект выполнив команду Maven: `mvn clean install`
* Запустите проект при помощи команды Maven: `mvn spring-boot:run`

  Изначально проект запускается на порту 8080 - `localhost:8080`, однако если этот порт у вас занят, вы можете изменить порт добавив в `application.yaml` следующее:

    ```yaml
   server:
      port: значение