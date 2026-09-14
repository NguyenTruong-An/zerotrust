package com.zerotrust.zerotrust.model.response;

import java.util.List;

public record BatchScoreResponseDTO(
        int created,
        int updated,
        List<ScoreResponseDTO> scores
) {
}
