package io.bytecloud.auth.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;
public record AuthResponse(
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("refresh_token") String refreshToken
) { }
