package io.bytecloud.auth.repository;

import io.bytecloud.auth.model.Role;
import io.bytecloud.auth.model.enums.RoleType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(RoleType name);

    @Query(value = """
        select r from Role r join fetch r.users u\s
        where u.id = :id
    """)
    Optional<Role> findByUserId(Long id);
}
