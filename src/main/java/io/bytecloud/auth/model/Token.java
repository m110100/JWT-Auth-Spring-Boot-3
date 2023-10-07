package io.bytecloud.auth.model;

import io.bytecloud.auth.model.enums.TokenType;
import jakarta.persistence.*;
import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@EqualsAndHashCode(exclude = "id")
@Builder
@Entity
@Table(name = "jwts")
public class Token {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String token;

    @Column(name = "type", nullable = false)
    @Enumerated(EnumType.STRING)
    private TokenType type = TokenType.BEARER;

    @Column(name = "revoked", nullable = false)
    private boolean revoked;

    @Column(name = "expired", nullable = false)
    private boolean expired;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
}
