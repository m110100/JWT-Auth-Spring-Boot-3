package io.bytecloud.auth.exception;

public class RoleNotFoundException extends NotFoundException{
    public RoleNotFoundException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public RoleNotFoundException(String msg) {
        super(msg);
    }
}
