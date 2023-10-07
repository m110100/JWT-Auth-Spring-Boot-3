package io.bytecloud.auth.dto.request;

public record AuthRequest(
    String email,
    String password
) { }
