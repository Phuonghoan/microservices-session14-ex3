package org.example.identityservice.dto;

public record TokenResponseDTO(
        String accessToken,
        String refreshToken
) {
}
