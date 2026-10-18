package org.example.identityservice.repository;

import org.example.identityservice.entity.RefreshToken;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import jakarta.persistence.LockModeType;

import java.util.Optional;

public interface RefreshTokenRepository
        extends JpaRepository<RefreshToken, Long> {

    // Method đã có từ bài trước
    Optional<RefreshToken> findByToken(String token);

    // Lấy token kèm khóa DB để tránh dùng đồng thời
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
        SELECT rt FROM RefreshToken rt
        WHERE rt.token = :token
    """)
    Optional<RefreshToken> findByTokenForUpdate(
            @Param("token") String token
    );
}
