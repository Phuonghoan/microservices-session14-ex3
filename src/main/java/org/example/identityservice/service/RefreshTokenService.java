package org.example.identityservice.service;

import org.example.identityservice.dto.TokenResponseDTO;
import org.example.identityservice.entity.RefreshToken;
import org.example.identityservice.entity.User;

import org.example.identityservice.repository.RefreshTokenRepository;
import org.example.identityservice.repository.UserRepository;

import org.example.identityservice.util.JwtUtil;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final long refreshTokenExpiration;

    public RefreshTokenService(
            RefreshTokenRepository refreshTokenRepository,
            UserRepository userRepository,
            JwtUtil jwtUtil,
            @Value("${app.jwt.refresh-token-expiration}")
            long refreshTokenExpiration
    ) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
        this.refreshTokenExpiration = refreshTokenExpiration;
    }

    // =====================================
    // BÀI TRƯỚC: TẠO REFRESH TOKEN
    // =====================================

    @Transactional
    public RefreshToken createRefreshToken(String userId) {

        User user = userRepository.findById(userId)
                .orElseThrow(() ->
                        new ResponseStatusException(
                                HttpStatus.NOT_FOUND,
                                "Không tìm thấy người dùng"
                        )
                );

        RefreshToken refreshToken = new RefreshToken();

        refreshToken.setUser(user);

        // Tạo UUID
        refreshToken.setToken(
                UUID.randomUUID().toString()
        );

        // Hết hạn sau 7 ngày
        refreshToken.setExpiryDate(
                Instant.now().plusMillis(
                        refreshTokenExpiration
                )
        );

        return refreshTokenRepository.save(refreshToken);
    }

    // =====================================
    // BÀI TRƯỚC: KIỂM TRA HẾT HẠN
    // =====================================

    public RefreshToken verifyExpiration(RefreshToken token) {

        if (!token.getExpiryDate().isAfter(Instant.now())) {

            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Refresh Token đã hết hạn"
            );
        }

        return token;
    }

    // =====================================
    // BÀI MỚI: REFRESH TOKEN ROTATION
    // =====================================

    @Transactional
    public TokenResponseDTO refreshToken(String requestToken) {

        // 1. Kiểm tra đầu vào
        if (requestToken == null || requestToken.isBlank()) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Refresh Token không hợp lệ"
            );
        }

        // 2. Tìm và khóa Refresh Token cũ
        RefreshToken oldToken = refreshTokenRepository
                .findByTokenForUpdate(requestToken)
                .orElseThrow(() ->
                        new ResponseStatusException(
                                HttpStatus.UNAUTHORIZED,
                                "Refresh Token không tồn tại hoặc đã bị thu hồi"
                        )
                );

        // 3. Kiểm tra hạn sử dụng
        verifyExpiration(oldToken);

        // 4. Lấy User sở hữu token
        User user = oldToken.getUser();

        // 5. Xóa Refresh Token cũ
        refreshTokenRepository.delete(oldToken);

        // Đẩy lệnh DELETE xuống PostgreSQL ngay trong transaction
        refreshTokenRepository.flush();

        // 6. Tạo Access Token mới (15 phút)
        String newAccessToken =
                jwtUtil.generateAccessToken(user);

        // 7. Tạo Refresh Token mới (7 ngày)
        RefreshToken newRefreshToken =
                createRefreshToken(user.getId());

        // 8. Trả về cặp token mới
        return new TokenResponseDTO(
                newAccessToken,
                newRefreshToken.getToken()
        );
    }
}
