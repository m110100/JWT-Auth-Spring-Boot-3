package io.bytecloud.auth.exception;

public class UserNotFoundException extends NotFoundException{
    public UserNotFoundException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public UserNotFoundException(String msg) {
        super(msg);
    }
}
