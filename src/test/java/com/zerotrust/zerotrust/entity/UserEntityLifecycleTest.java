package com.zerotrust.zerotrust.entity;

import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;

class UserEntityLifecycleTest {

    @Test
    void initializesAuditFieldsAndDeletedAtBeforeInsert() {
        UserEntity user = new UserEntity();
        user.setStatus(UserEntity.Status.DELETED);

        user.initializeTimestamps();

        assertThat(user.getCreatedAt()).isNotNull();
        assertThat(user.getUpdatedAt()).isNotNull();
        assertThat(user.getDeletedAt()).isNotNull();
    }

    @Test
    void preservesDeletedAtOnSubsequentUpdates() {
        UserEntity user = new UserEntity();
        LocalDateTime deletedAt = LocalDateTime.now().minusDays(1);
        user.setStatus(UserEntity.Status.DELETED);
        user.setDeletedAt(deletedAt);

        user.updateTimestamp();

        assertThat(user.getDeletedAt()).isEqualTo(deletedAt);
        assertThat(user.getUpdatedAt()).isNotNull();
    }

    @Test
    void clearsDeletedAtWhenUserIsRestored() {
        UserEntity user = new UserEntity();
        user.setStatus(UserEntity.Status.ACTIVE);
        user.setDeletedAt(LocalDateTime.now().minusDays(1));

        user.updateTimestamp();

        assertThat(user.getDeletedAt()).isNull();
    }
}
