package com.zerotrust.risk.repository;

import com.zerotrust.risk.entity.KnownDeviceEntity;

import java.util.List;

public interface KnownDeviceRevocationRepository {
    List<KnownDeviceEntity> findCurrentForRevocation(String subjectId);
}
